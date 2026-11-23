pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Respaldo de solo dependencias de test Kotlin/JUnit cuando Maven Central no responde.
        maven {
            url = uri("https://maven.wso2.org/nexus/content/repositories/central/")
            content {
                includeGroup("org.jetbrains.kotlin")
                includeGroup("org.junit.jupiter")
                includeGroup("org.junit.platform")
                includeGroup("org.opentest4j")
                includeGroup("org.apiguardian")
            }
        }
        maven { url = uri("$rootDir/build/firestack-maven") }
    }
}
rootProject.name = "FirewallDNS"
include(":app", ":engine-core", ":dns-engine", ":threat-engine", ":engine-monitor", ":engine-runtime", ":android-adapter")
