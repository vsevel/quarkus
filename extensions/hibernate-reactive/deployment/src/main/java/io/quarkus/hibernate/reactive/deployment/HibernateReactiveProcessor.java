package io.quarkus.hibernate.reactive.deployment;

import static io.quarkus.deployment.annotations.ExecutionTime.RUNTIME_INIT;
import static io.quarkus.deployment.annotations.ExecutionTime.STATIC_INIT;
import static io.quarkus.hibernate.orm.deployment.HibernateConfigUtil.firstPresent;
import static io.quarkus.hibernate.orm.runtime.PersistenceUnitUtil.DEFAULT_PERSISTENCE_UNIT_NAME;
import static org.hibernate.cfg.AvailableSettings.JAKARTA_HBM2DDL_DB_VERSION;
import static org.hibernate.cfg.AvailableSettings.JAKARTA_SHARED_CACHE_MODE;
import static org.hibernate.cfg.AvailableSettings.STORAGE_ENGINE;
import static org.hibernate.cfg.AvailableSettings.USE_DIRECT_REFERENCE_CACHE_ENTRIES;
import static org.hibernate.cfg.AvailableSettings.USE_QUERY_CACHE;
import static org.hibernate.cfg.AvailableSettings.USE_SECOND_LEVEL_CACHE;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.stream.Collectors;

import jakarta.persistence.SharedCacheMode;
import jakarta.persistence.ValidationMode;
import jakarta.persistence.spi.PersistenceUnitTransactionType;

import org.hibernate.cfg.AvailableSettings;
import org.hibernate.loader.BatchFetchStyle;
import org.hibernate.reactive.provider.impl.ReactiveIntegrator;
import org.jboss.logging.Logger;

import io.quarkus.arc.deployment.RecorderBeanInitializedBuildItem;
import io.quarkus.arc.deployment.UnremovableBeanBuildItem;
import io.quarkus.datasource.common.runtime.DataSourceUtil;
import io.quarkus.datasource.common.runtime.DatabaseKind;
import io.quarkus.datasource.deployment.spi.DefaultDataSourceDbKindBuildItem;
import io.quarkus.datasource.runtime.DataSourceBuildTimeConfig;
import io.quarkus.datasource.runtime.DataSourcesBuildTimeConfig;
import io.quarkus.deployment.Capabilities;
import io.quarkus.deployment.Capability;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.ApplicationArchivesBuildItem;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.deployment.builditem.HotDeploymentWatchedFileBuildItem;
import io.quarkus.deployment.builditem.LaunchModeBuildItem;
import io.quarkus.deployment.builditem.LogCategoryBuildItem;
import io.quarkus.deployment.builditem.SystemPropertyBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ServiceProviderBuildItem;
import io.quarkus.deployment.pkg.builditem.CurateOutcomeBuildItem;
import io.quarkus.deployment.recording.RecorderContext;
import io.quarkus.hibernate.orm.deployment.HibernateConfigUtil;
import io.quarkus.hibernate.orm.deployment.HibernateOrmConfig;
import io.quarkus.hibernate.orm.deployment.HibernateOrmConfigPersistenceUnit;
import io.quarkus.hibernate.orm.deployment.HibernateOrmConfigPersistenceUnit.IdentifierQuotingStrategy;
import io.quarkus.hibernate.orm.deployment.HibernateOrmProcessor;
import io.quarkus.hibernate.orm.deployment.JpaModelBuildItem;
import io.quarkus.hibernate.orm.deployment.PersistenceProviderSetUpBuildItem;
import io.quarkus.hibernate.orm.deployment.PersistenceUnitDescriptorBuildItem;
import io.quarkus.hibernate.orm.deployment.PersistenceXmlDescriptorBuildItem;
import io.quarkus.hibernate.orm.deployment.integration.HibernateOrmIntegrationRuntimeConfiguredBuildItem;
import io.quarkus.hibernate.orm.deployment.spi.DatabaseKindDialectBuildItem;
import io.quarkus.hibernate.orm.runtime.HibernateOrmRuntimeConfig;
import io.quarkus.hibernate.orm.runtime.boot.QuarkusPersistenceUnitDescriptor;
import io.quarkus.hibernate.orm.runtime.customized.FormatMapperKind;
import io.quarkus.hibernate.orm.runtime.recording.RecordedConfig;
import io.quarkus.hibernate.reactive.runtime.FastBootHibernateReactivePersistenceProvider;
import io.quarkus.hibernate.reactive.runtime.HibernateReactive;
import io.quarkus.hibernate.reactive.runtime.HibernateReactiveRecorder;
import io.quarkus.reactive.datasource.deployment.VertxPoolBuildItem;
import io.quarkus.reactive.datasource.runtime.DataSourcesReactiveBuildTimeConfig;
import io.quarkus.runtime.LaunchMode;
import io.quarkus.runtime.configuration.ConfigurationException;

@BuildSteps(onlyIf = HibernateReactiveEnabled.class)
public final class HibernateReactiveProcessor {

    private static final String HIBERNATE_REACTIVE = "Hibernate Reactive";
    private static final Logger LOG = Logger.getLogger(HibernateReactiveProcessor.class);
    static final String[] REFLECTIVE_CONSTRUCTORS_NEEDED = {
            "org.hibernate.reactive.persister.entity.impl.ReactiveSingleTableEntityPersister",
            "org.hibernate.reactive.persister.entity.impl.ReactiveJoinedSubclassEntityPersister",
            "org.hibernate.reactive.persister.entity.impl.ReactiveUnionSubclassEntityPersister",
            "org.hibernate.reactive.persister.collection.impl.ReactiveOneToManyPersister",
            "org.hibernate.reactive.persister.collection.impl.ReactiveBasicCollectionPersister",
    };

    @BuildStep
    void registerServicesForReflection(BuildProducer<ServiceProviderBuildItem> services) {
        services.produce(new ServiceProviderBuildItem(
                "io.vertx.core.spi.VertxServiceProvider",
                "org.hibernate.reactive.context.impl.ContextualDataStorage"));
    }

    @BuildStep
    void reflections(BuildProducer<ReflectiveClassBuildItem> reflectiveClass) {
        reflectiveClass.produce(new ReflectiveClassBuildItem(false, false, REFLECTIVE_CONSTRUCTORS_NEEDED));
    }

    @BuildStep
    @Record(STATIC_INIT)
    public void build(RecorderContext recorderContext,
            HibernateReactiveRecorder recorder,
            JpaModelBuildItem jpaModel) {
        final boolean enableRx = hasEntities(jpaModel);
        recorder.callHibernateReactiveFeatureInit(enableRx);
    }

    @BuildStep
    public void buildReactivePersistenceUnit(
            HibernateOrmConfig hibernateOrmConfig, CombinedIndexBuildItem index,
            DataSourcesBuildTimeConfig dataSourcesBuildTimeConfig,
            DataSourcesReactiveBuildTimeConfig dataSourcesReactiveBuildTimeConfig,
            List<PersistenceXmlDescriptorBuildItem> persistenceXmlDescriptors,
            ApplicationArchivesBuildItem applicationArchivesBuildItem,
            LaunchModeBuildItem launchMode,
            JpaModelBuildItem jpaModel,
            Capabilities capabilities,
            BuildProducer<SystemPropertyBuildItem> systemProperties,
            BuildProducer<NativeImageResourceBuildItem> nativeImageResources,
            BuildProducer<HotDeploymentWatchedFileBuildItem> hotDeploymentWatchedFiles,
            BuildProducer<PersistenceUnitDescriptorBuildItem> persistenceUnitDescriptors,
            List<DefaultDataSourceDbKindBuildItem> defaultDataSourceDbKindBuildItems,
            CurateOutcomeBuildItem curateOutcomeBuildItem,
            BuildProducer<UnremovableBeanBuildItem> unremovableBeans,
            List<DatabaseKindDialectBuildItem> dbKindDialectBuildItems) {

        final boolean enableHR = hasEntities(jpaModel);
        if (!enableHR) {
            // we have to bail out early as we might not have a Vertx pool configuration
            LOG.warn("Hibernate Reactive is disabled because no JPA entities were found");
            return;
        }

        // Block any reactive persistence units from using persistence.xml
        for (PersistenceXmlDescriptorBuildItem persistenceXmlDescriptorBuildItem : persistenceXmlDescriptors) {
            String provider = persistenceXmlDescriptorBuildItem.getDescriptor().getProviderClassName();
            if (provider == null ||
                    provider.equals(FastBootHibernateReactivePersistenceProvider.class.getCanonicalName()) ||
                    provider.equals(FastBootHibernateReactivePersistenceProvider.IMPLEMENTATION_NAME)) {
                throw new ConfigurationException(
                        "Cannot use persistence.xml with Hibernate Reactive in Quarkus. Must use application.properties instead.");
            }
        }
        HibernateOrmConfigPersistenceUnit persistenceUnitConfig = hibernateOrmConfig.defaultPersistenceUnit();

        String datasourceNameFromConf = persistenceUnitConfig.datasource().orElse(DataSourceUtil.DEFAULT_DATASOURCE_NAME);

        DataSourceBuildTimeConfig defaultDataSourceBuildTimeConfig = dataSourcesBuildTimeConfig.dataSources()
                .get(DataSourceUtil.DEFAULT_DATASOURCE_NAME);

        DataSourceBuildTimeConfig dataSourceBuildTimeConfig = dataSourcesBuildTimeConfig.dataSources()
                .get(datasourceNameFromConf);

        Optional<String> datasourceName = Optional.of(datasourceNameFromConf);
        Optional<String> explicitDialect = hibernateOrmConfig.defaultPersistenceUnit().dialect().dialect();
        Optional<String> explicitDbMinVersion = defaultDataSourceBuildTimeConfig.dbVersion();
        Optional<String> dbKindOptional = DefaultDataSourceDbKindBuildItem.resolve(
                dataSourceBuildTimeConfig.dbKind(),
                defaultDataSourceDbKindBuildItems,
                defaultDataSourceBuildTimeConfig.devservices().enabled()
                        .orElse(!dataSourcesBuildTimeConfig.hasNamedDataSources()),
                curateOutcomeBuildItem);
        Optional<String> dbVersion = dataSourceBuildTimeConfig.dbVersion();

        if (dbKindOptional.isEmpty()) {
            throw new ConfigurationException(
                    "The datasource must be configured for Hibernate Reactive. Refer to https://quarkus.io/guides/datasource for guidance.",
                    Set.of("quarkus.datasource.db-kind", "quarkus.datasource.username",
                            "quarkus.datasource.password"));
        }

        // We only support Hibernate Reactive with a reactive data source, otherwise we don't configure the PU
        DataSourcesReactiveBuildTimeConfig.DataSourceReactiveOuterNamedBuildTimeConfig dataSourceReactiveBuildTimeConfig = dataSourcesReactiveBuildTimeConfig
                .dataSources().get(datasourceNameFromConf);

        if (dataSourceReactiveBuildTimeConfig == null || !dataSourceReactiveBuildTimeConfig.reactive().enabled()) {
            LOG.warn("Hibernate Reactive is disabled because the datasource is not reactive");
            return;
        }

        QuarkusPersistenceUnitDescriptor reactivePU = generateReactivePersistenceUnit(
                hibernateOrmConfig, index, persistenceUnitConfig, jpaModel,
                dbKindOptional, explicitDialect, explicitDbMinVersion, applicationArchivesBuildItem,
                launchMode.getLaunchMode(),
                systemProperties, nativeImageResources, hotDeploymentWatchedFiles, dbKindDialectBuildItems);

        Optional<FormatMapperKind> jsonMapper = jsonMapperKind(capabilities);
        Optional<FormatMapperKind> xmlMapper = xmlMapperKind(capabilities);
        jsonMapper.flatMap(FormatMapperKind::requiredBeanType)
                .ifPresent(type -> unremovableBeans.produce(UnremovableBeanBuildItem.beanClassNames(type)));
        xmlMapper.flatMap(FormatMapperKind::requiredBeanType)
                .ifPresent(type -> unremovableBeans.produce(UnremovableBeanBuildItem.beanClassNames(type)));

        //Some constant arguments to the following method:
        // - this is Reactive
        // - we don't support starting Hibernate Reactive from a persistence.xml
        // - we don't support Hibernate Envers with Hibernate Reactive
        persistenceUnitDescriptors.produce(new PersistenceUnitDescriptorBuildItem(reactivePU,
                new RecordedConfig(
                        datasourceName,
                        dbKindOptional,
                        dbVersion,
                        persistenceUnitConfig.dialect().dialect(),
                        io.quarkus.hibernate.orm.runtime.migration.MultiTenancyStrategy.NONE,
                        hibernateOrmConfig.database().ormCompatibilityVersion(),
                        persistenceUnitConfig.unsupportedProperties()),
                null,
                jpaModel.getXmlMappings(reactivePU.getName()),
                false,
                isHibernateValidatorPresent(capabilities), jsonMapper, xmlMapper));
    }

    @BuildStep
    void waitForVertxPool(List<VertxPoolBuildItem> vertxPool,
            List<PersistenceUnitDescriptorBuildItem> persistenceUnitDescriptorBuildItems,
            BuildProducer<HibernateOrmIntegrationRuntimeConfiguredBuildItem> runtimeConfigured) {
        for (PersistenceUnitDescriptorBuildItem puDescriptor : persistenceUnitDescriptorBuildItems) {
            // Define a dependency on VertxPoolBuildItem to ensure that any Pool instances are available
            // when HibernateORM starts its persistence units
            runtimeConfigured.produce(new HibernateOrmIntegrationRuntimeConfiguredBuildItem(HIBERNATE_REACTIVE,
                    puDescriptor.getPersistenceUnitName()));
        }
    }

    @BuildStep
    @Record(RUNTIME_INIT)
    PersistenceProviderSetUpBuildItem setUpPersistenceProviderAndWaitForVertxPool(HibernateReactiveRecorder recorder,
            HibernateOrmRuntimeConfig hibernateOrmRuntimeConfig,
            List<HibernateOrmIntegrationRuntimeConfiguredBuildItem> integrationBuildItems,
            BuildProducer<RecorderBeanInitializedBuildItem> orderEnforcer) {
        recorder.initializePersistenceProvider(hibernateOrmRuntimeConfig,
                HibernateOrmIntegrationRuntimeConfiguredBuildItem.collectDescriptors(integrationBuildItems));
        return new PersistenceProviderSetUpBuildItem();
    }

    @BuildStep
    void silenceLogging(BuildProducer<LogCategoryBuildItem> logCategories) {
        logCategories.produce(new LogCategoryBuildItem(ReactiveIntegrator.class.getName(), Level.WARNING));
    }

    /**
     * This is mostly copied from
     * io.quarkus.hibernate.orm.deployment.HibernateOrmProcessor#handleHibernateORMWithNoPersistenceXml
     * Key differences are:
     * - Always produces a persistence unit descriptor, since we assume there always 1 reactive persistence unit
     * - Any JDBC-only configuration settings are removed
     * - If we ever add any Reactive-only config settings, they can be set here
     */
    // TODO this whole method is really just a hack that duplicates
    //  io.quarkus.hibernate.orm.deployment.HibernateOrmProcessor.handleHibernateORMWithNoPersistenceXml
    //  and customizes it for Hibernate Reactive.
    //  we should work on a way to merge the two methods while still having some behavior specific to
    //  HR/ORM, because it's likely the HR implementation is missing some features,
    //  and we've seen in the past that features we add to handleHibernateORMWithNoPersistenceXml
    //  tend not to be added here.
    //  See https://github.com/quarkusio/quarkus/issues/28629.
    //see producePersistenceUnitDescriptorFromConfig in ORM
    private static QuarkusPersistenceUnitDescriptor generateReactivePersistenceUnit(
            HibernateOrmConfig hibernateOrmConfig, CombinedIndexBuildItem index,
            HibernateOrmConfigPersistenceUnit persistenceUnitConfig,
            JpaModelBuildItem jpaModel,
            Optional<String> dbKindOptional,
            Optional<String> explicitDialect,
            Optional<String> explicitDbMinVersion,
            ApplicationArchivesBuildItem applicationArchivesBuildItem,
            LaunchMode launchMode,
            BuildProducer<SystemPropertyBuildItem> systemProperties,
            BuildProducer<NativeImageResourceBuildItem> nativeImageResources,
            BuildProducer<HotDeploymentWatchedFileBuildItem> hotDeploymentWatchedFiles,
            List<DatabaseKindDialectBuildItem> dbKindDialectBuildItems) {
        //we have no persistence.xml so we will create a default one
        String persistenceUnitConfigName = DEFAULT_PERSISTENCE_UNIT_NAME;

        Map<String, Set<String>> modelClassesAndPackagesPerPersistencesUnits = HibernateOrmProcessor
                .getModelClassesAndPackagesPerPersistenceUnits(hibernateOrmConfig, jpaModel, index.getIndex(), true);
        Set<String> nonDefaultPUWithModelClassesOrPackages = modelClassesAndPackagesPerPersistencesUnits.entrySet().stream()
                .filter(e -> !DEFAULT_PERSISTENCE_UNIT_NAME.equals(e.getKey()) && !e.getValue().isEmpty())
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
        if (!nonDefaultPUWithModelClassesOrPackages.isEmpty()) {
            // Not supported yet; see https://github.com/quarkusio/quarkus/issues/21110
            LOG.warnf("Entities are affected to non-default Hibernate Reactive persistence units %s."
                    + " Since Hibernate Reactive only works with the default persistence unit, those entities will be ignored.",
                    nonDefaultPUWithModelClassesOrPackages);
        }
        Set<String> modelClassesAndPackages = modelClassesAndPackagesPerPersistencesUnits
                .getOrDefault(DEFAULT_PERSISTENCE_UNIT_NAME, Collections.emptySet());

        if (modelClassesAndPackages.isEmpty()) {
            LOG.warnf("Could not find any entities affected to the Hibernate Reactive persistence unit.");
        }

        QuarkusPersistenceUnitDescriptor desc = new QuarkusPersistenceUnitDescriptor(
                HibernateReactive.DEFAULT_REACTIVE_PERSISTENCE_UNIT_NAME, persistenceUnitConfigName,
                PersistenceUnitTransactionType.RESOURCE_LOCAL,
                new ArrayList<>(modelClassesAndPackages),
                new Properties(),
                true);

        setDialectAndStorageEngine(dbKindOptional, explicitDialect, explicitDbMinVersion, dbKindDialectBuildItems,
                persistenceUnitConfig.dialect().storageEngine(), systemProperties, desc);

        // Physical Naming Strategy
        persistenceUnitConfig.physicalNamingStrategy().ifPresent(
                namingStrategy -> desc.getProperties()
                        .setProperty(AvailableSettings.PHYSICAL_NAMING_STRATEGY, namingStrategy));

        // Implicit Naming Strategy
        persistenceUnitConfig.implicitNamingStrategy().ifPresent(
                namingStrategy -> desc.getProperties()
                        .setProperty(AvailableSettings.IMPLICIT_NAMING_STRATEGY, namingStrategy));

        // Mapping
        if (persistenceUnitConfig.mapping().timezone().timeZoneDefaultStorage().isPresent()) {
            desc.getProperties().setProperty(AvailableSettings.TIMEZONE_DEFAULT_STORAGE,
                    persistenceUnitConfig.mapping().timezone().timeZoneDefaultStorage().get().name());
        }
        desc.getProperties().setProperty(AvailableSettings.PREFERRED_POOLED_OPTIMIZER,
                persistenceUnitConfig.mapping().id().optimizer().idOptimizerDefault()
                        .orElse(HibernateOrmConfigPersistenceUnit.IdOptimizerType.POOLED_LO).configName);

        //charset
        desc.getProperties().setProperty(AvailableSettings.HBM2DDL_CHARSET_NAME,
                persistenceUnitConfig.database().charset().name());

        // Quoting strategy
        if (persistenceUnitConfig.quoteIdentifiers().strategy() == IdentifierQuotingStrategy.ALL
                || persistenceUnitConfig.quoteIdentifiers()
                        .strategy() == IdentifierQuotingStrategy.ALL_EXCEPT_COLUMN_DEFINITIONS
                || persistenceUnitConfig.database().globallyQuotedIdentifiers()) {
            desc.getProperties().setProperty(AvailableSettings.GLOBALLY_QUOTED_IDENTIFIERS, "true");
        }
        if (persistenceUnitConfig.quoteIdentifiers().strategy() == IdentifierQuotingStrategy.ALL_EXCEPT_COLUMN_DEFINITIONS) {
            desc.getProperties().setProperty(AvailableSettings.GLOBALLY_QUOTED_IDENTIFIERS_SKIP_COLUMN_DEFINITIONS, "true");
        } else if (persistenceUnitConfig.quoteIdentifiers().strategy() == IdentifierQuotingStrategy.ONLY_KEYWORDS) {
            desc.getProperties().setProperty(AvailableSettings.KEYWORD_AUTO_QUOTING_ENABLED, "true");
        }

        // Query
        // TODO ideally we should align on ORM and use 16 as a default, but that would break applications
        //   because of https://github.com/hibernate/hibernate-reactive/issues/742
        int batchSize = firstPresent(persistenceUnitConfig.fetch().batchSize(), persistenceUnitConfig.batchFetchSize())
                .orElse(-1);
        if (batchSize > 0) {
            desc.getProperties().setProperty(AvailableSettings.DEFAULT_BATCH_FETCH_SIZE,
                    Integer.toString(batchSize));
            desc.getProperties().setProperty(AvailableSettings.BATCH_FETCH_STYLE, BatchFetchStyle.PADDED.toString());
        }

        if (persistenceUnitConfig.fetch().maxDepth().isPresent()) {
            setMaxFetchDepth(desc, persistenceUnitConfig.fetch().maxDepth());
        } else if (persistenceUnitConfig.maxFetchDepth().isPresent()) {
            setMaxFetchDepth(desc, persistenceUnitConfig.maxFetchDepth());
        }

        desc.getProperties().setProperty(AvailableSettings.QUERY_PLAN_CACHE_MAX_SIZE, Integer.toString(
                persistenceUnitConfig.query().queryPlanCacheMaxSize()));

        desc.getProperties().setProperty(AvailableSettings.DEFAULT_NULL_ORDERING,
                persistenceUnitConfig.query().defaultNullOrdering().name().toLowerCase());

        desc.getProperties().setProperty(AvailableSettings.IN_CLAUSE_PARAMETER_PADDING,
                String.valueOf(persistenceUnitConfig.query().inClauseParameterPadding()));

        // JDBC
        persistenceUnitConfig.jdbc().timezone().ifPresent(
                timezone -> desc.getProperties().setProperty(AvailableSettings.JDBC_TIME_ZONE, timezone));

        persistenceUnitConfig.jdbc().statementFetchSize().ifPresent(
                fetchSize -> desc.getProperties().setProperty(AvailableSettings.STATEMENT_FETCH_SIZE,
                        String.valueOf(fetchSize)));

        persistenceUnitConfig.jdbc().statementBatchSize().ifPresent(
                statementBatchSize -> desc.getProperties().setProperty(AvailableSettings.STATEMENT_BATCH_SIZE,
                        String.valueOf(statementBatchSize)));

        // Statistics
        if (hibernateOrmConfig.metrics().enabled()
                || (hibernateOrmConfig.statistics().isPresent() && hibernateOrmConfig.statistics().get())) {
            desc.getProperties().setProperty(AvailableSettings.GENERATE_STATISTICS, "true");
        }

        // sql-load-script
        List<String> importFiles = getSqlLoadScript(persistenceUnitConfig.sqlLoadScript(), launchMode);

        if (!importFiles.isEmpty()) {
            for (String importFile : importFiles) {
                Path loadScriptPath = applicationArchivesBuildItem.getRootArchive().getChildPath(importFile);

                if (loadScriptPath != null && !Files.isDirectory(loadScriptPath)) {
                    // enlist resource if present
                    nativeImageResources.produce(new NativeImageResourceBuildItem(importFile));
                    hotDeploymentWatchedFiles.produce(new HotDeploymentWatchedFileBuildItem(importFile));
                } else if (persistenceUnitConfig.sqlLoadScript().isPresent()) {
                    //raise exception if explicit file is not present (i.e. not the default)
                    String propertyName = HibernateOrmRuntimeConfig.puPropertyKey(persistenceUnitConfigName, "sql-load-script");
                    throw new ConfigurationException(
                            "Unable to find file referenced in '"
                                    + propertyName + "="
                                    + String.join(",", persistenceUnitConfig.sqlLoadScript().get())
                                    + "'. Remove property or add file to your path.",
                            Collections.singleton(propertyName));
                }
            }

            if (persistenceUnitConfig.sqlLoadScript().isPresent()) {
                desc.getProperties().setProperty(AvailableSettings.HBM2DDL_IMPORT_FILES, String.join(",", importFiles));
            }
        } else {
            //Disable implicit loading of the default import script (import.sql)
            desc.getProperties().setProperty(AvailableSettings.HBM2DDL_IMPORT_FILES, "");
            desc.getProperties().setProperty(AvailableSettings.HBM2DDL_SKIP_DEFAULT_IMPORT_FILE, "true");
        }

        // Caching
        if (persistenceUnitConfig.secondLevelCachingEnabled()) {
            Properties p = desc.getProperties();
            //Only set these if the user isn't making an explicit choice:
            p.putIfAbsent(USE_DIRECT_REFERENCE_CACHE_ENTRIES, Boolean.TRUE);
            p.putIfAbsent(USE_SECOND_LEVEL_CACHE, Boolean.TRUE);
            p.putIfAbsent(USE_QUERY_CACHE, Boolean.TRUE);
            p.putIfAbsent(JAKARTA_SHARED_CACHE_MODE, SharedCacheMode.ENABLE_SELECTIVE);
            Map<String, String> cacheConfigEntries = HibernateConfigUtil.getCacheConfigEntries(persistenceUnitConfig);
            for (Entry<String, String> entry : cacheConfigEntries.entrySet()) {
                desc.getProperties().setProperty(entry.getKey(), entry.getValue());
            }
        } else {
            //Unless the global switch is explicitly set to off, in which case we disable all caching:
            Properties p = desc.getProperties();
            p.put(USE_DIRECT_REFERENCE_CACHE_ENTRIES, Boolean.FALSE);
            p.put(USE_SECOND_LEVEL_CACHE, Boolean.FALSE);
            p.put(USE_QUERY_CACHE, Boolean.FALSE);
            p.put(JAKARTA_SHARED_CACHE_MODE, SharedCacheMode.NONE);
        }

        if (!persistenceUnitConfig.validation().enabled()) {
            desc.getProperties().setProperty(AvailableSettings.JAKARTA_VALIDATION_MODE, ValidationMode.NONE.name());
        } else {
            desc.getProperties().setProperty(
                    AvailableSettings.JAKARTA_VALIDATION_MODE,
                    persistenceUnitConfig.validation().mode()
                            .stream()
                            .map(Enum::name)
                            .collect(Collectors.joining(",")));
        }

        return desc;
    }

    private static void setDialectAndStorageEngine(Optional<String> dbKind, Optional<String> explicitDialect,
            Optional<String> explicitDbMinVersion, List<DatabaseKindDialectBuildItem> dbKindDialectBuildItems,
            Optional<String> storageEngine, BuildProducer<SystemPropertyBuildItem> systemProperties,
            QuarkusPersistenceUnitDescriptor desc) {
        final String persistenceUnitName = DEFAULT_PERSISTENCE_UNIT_NAME;
        Optional<String> dialect = explicitDialect;
        Optional<String> dbProductName = Optional.empty();
        Optional<String> dbProductVersion = explicitDbMinVersion;
        if (dbKind.isPresent() || explicitDialect.isPresent()) {
            for (DatabaseKindDialectBuildItem item : dbKindDialectBuildItems) {
                if (dbKind.isPresent() && DatabaseKind.is(dbKind.get(), item.getDbKind())
                        // Set the default version based on the dialect when we don't have a datasource
                        // (i.e. for database multi-tenancy)
                        || explicitDialect.isPresent() && item.getMatchingDialects().contains(explicitDialect.get())) {
                    dbProductName = item.getDatabaseProductName();
                    if (dbProductName.isEmpty() && explicitDialect.isEmpty()) {
                        // Use dialects only as a last resort, prefer product name or explicitly user-provided dialect
                        dialect = item.getDialectOptional();
                    }
                    if (explicitDbMinVersion.isEmpty()) {
                        dbProductVersion = item.getDefaultDatabaseProductVersion();
                    }
                    break;
                }
            }
            if (dialect.isEmpty() && dbProductName.isEmpty()) {
                throw new ConfigurationException(
                        "The Hibernate Reactive extension could not guess the dialect from the database kind '"
                                + dbKind.get()
                                + "'. Add an explicit '"
                                + HibernateOrmRuntimeConfig.puPropertyKey(persistenceUnitName, "dialect")
                                + "' property.");
            }
        }

        if (dialect.isPresent()) {
            desc.getProperties().setProperty(AvailableSettings.DIALECT, dialect.get());
        } else if (dbProductName.isPresent()) {
            desc.getProperties().setProperty(AvailableSettings.JAKARTA_HBM2DDL_DB_NAME, dbProductName.get());
        } else {
            // We only get here with the database multi-tenancy strategy; see the initial check, up top.
            throw new ConfigurationException(String.format(Locale.ROOT,
                    "The Hibernate Reactive extension could not infer the dialect for persistence unit '%s'."
                            + " When using database multi-tenancy, you must either configure a datasource for that persistence unit"
                            + " (refer to https://quarkus.io/guides/datasource for guidance),"
                            + " or set the dialect explicitly through property '"
                            + HibernateOrmRuntimeConfig.puPropertyKey(persistenceUnitName, "dialect") + "'.",
                    persistenceUnitName));
        }

        // The storage engine has to be set as a system property.
        if (storageEngine.isPresent()) {
            systemProperties.produce(new SystemPropertyBuildItem(STORAGE_ENGINE, storageEngine.get()));
            // Only actually set the storage engines if MySQL or MariaDB
            if (isMySQLOrMariaDB(dbKind, dialect)) {
                systemProperties.produce(new SystemPropertyBuildItem(STORAGE_ENGINE, storageEngine.get()));
            } else {
                LOG.warnf("The storage engine set through configuration property '%1$s' is being ignored"
                        + " because the database is neither MySQL nor MariaDB.",
                        HibernateOrmRuntimeConfig.puPropertyKey(persistenceUnitName, "dialect.storage-engine"));
            }
        }

        if (dbProductVersion.isPresent()) {
            desc.getProperties().setProperty(JAKARTA_HBM2DDL_DB_VERSION, dbProductVersion.get());
        }
    }

    private static boolean isMySQLOrMariaDB(Optional<String> dbKind, Optional<String> dialect) {
        if (dbKind.isPresent() && (DatabaseKind.isMySQL(dbKind.get()) || DatabaseKind.isMariaDB(dbKind.get()))) {
            return true;
        }
        if (dialect.isPresent()) {
            String lowercaseDialect = dialect.get().toLowerCase(Locale.ROOT);
            return lowercaseDialect.contains("mysql") || lowercaseDialect.contains("mariadb");
        }
        return false;
    }

    private static void setMaxFetchDepth(QuarkusPersistenceUnitDescriptor descriptor, OptionalInt maxFetchDepth) {
        descriptor.getProperties().setProperty(AvailableSettings.MAX_FETCH_DEPTH, String.valueOf(maxFetchDepth.getAsInt()));
    }

    private static List<String> getSqlLoadScript(Optional<List<String>> sqlLoadScript, LaunchMode launchMode) {
        // Explicit file or default Hibernate ORM file.
        if (sqlLoadScript.isPresent()) {
            return sqlLoadScript.get().stream()
                    .filter(s -> !HibernateOrmProcessor.NO_SQL_LOAD_SCRIPT_FILE.equalsIgnoreCase(s))
                    .collect(Collectors.toList());
        } else if (launchMode == LaunchMode.NORMAL) {
            return Collections.emptyList();
        } else {
            return List.of("import.sql");
        }
    }

    private boolean hasEntities(JpaModelBuildItem jpaModel) {
        return !jpaModel.getEntityClassNames().isEmpty();
    }

    private static Optional<FormatMapperKind> jsonMapperKind(Capabilities capabilities) {
        if (capabilities.isPresent(Capability.JACKSON)) {
            return Optional.of(FormatMapperKind.JACKSON);
        }
        if (capabilities.isPresent(Capability.JSONB)) {
            return Optional.of(FormatMapperKind.JSONB);
        }
        return Optional.empty();
    }

    private static Optional<FormatMapperKind> xmlMapperKind(Capabilities capabilities) {
        if (capabilities.isPresent(Capability.JAXB)) {
            return Optional.of(FormatMapperKind.JAXB);
        }
        return Optional.empty();
    }

    private static boolean isHibernateValidatorPresent(Capabilities capabilities) {
        return capabilities.isPresent(Capability.HIBERNATE_VALIDATOR);
    }
}
