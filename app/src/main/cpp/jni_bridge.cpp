#include <jni.h>
#include <string>
#include "root_stage.h"

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_oplusace5_root_MainActivity_nativeRun(JNIEnv *env, jclass clazz, jstring jpath, jstring jlibdir) {
    (void) clazz;
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    const char *libdir = env->GetStringUTFChars(jlibdir, nullptr);
    std::string r = root_stage_start(path, libdir);
    env->ReleaseStringUTFChars(jpath, path);
    env->ReleaseStringUTFChars(jlibdir, libdir);
    return env->NewStringUTF(r.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_oplusace5_root_MainActivity_nativeStatus(JNIEnv *env, jclass clazz, jstring jpath) {
    (void) clazz;
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    std::string r = root_stage_status(path);
    env->ReleaseStringUTFChars(jpath, path);
    return env->NewStringUTF(r.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_oplusace5_root_MainActivity_nativeExec(JNIEnv *env, jclass clazz, jstring jcmd) {
    (void) clazz;
    const char *cmd = env->GetStringUTFChars(jcmd, nullptr);
    std::string r = root_exec(cmd);
    env->ReleaseStringUTFChars(jcmd, cmd);
    return env->NewStringUTF(r.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_oplusace5_root_MainActivity_nativeDaemon(JNIEnv *env, jclass clazz) {
    (void) clazz;
    std::string banner;
    return env->NewStringUTF(root_daemon_alive(&banner) ? banner.c_str() : "");
}
