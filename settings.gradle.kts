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
        maven { url = uri("$rootDir/build/firestack-maven") }
    }
}
rootProject.name = "FirewallDNS"
include(":app", ":engine-core", ":dns-engine", ":threat-engine", ":engine-monitor", ":engine-runtime", ":android-adapter")
