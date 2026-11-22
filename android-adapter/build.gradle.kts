plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    sourceSets.getByName("main").jniLibs.srcDir(layout.buildDirectory.dir("generated/jniLibs"))
    namespace = "com.firewalldns.engine.android"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation(files("libs/tun2socks.aar"))
    api(project(":dns-engine"))
    api(project(":engine-runtime"))
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito:mockito-core:5.15.2")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}

 
// Build the JNI shared library for the Samsung A34 ARM64 target.
val cargoBuildArm64 by tasks.registering(Exec::class) {
    val rustRoot = rootProject.layout.projectDirectory.dir("rust-core")
    val jniLibs = layout.buildDirectory.dir("generated/jniLibs")
    val output = jniLibs.map { it.file("arm64-v8a/libfirewalldns_native.so") }
    workingDir(rustRoot)
    inputs.files(fileTree(rustRoot) { exclude("target/**") })
    outputs.file(output)
    doFirst { jniLibs.get().asFile.mkdirs() }
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-o", jniLibs.get().asFile.absolutePath,
        "build", "--release",
    )
}

tasks.named("preBuild").configure {
    dependsOn(cargoBuildArm64)
}
