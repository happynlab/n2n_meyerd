//
// Created by switchwang(https://github.com/switch-st) on 2018-04-15.
//

#include <jni.h>
#include <pthread.h>
#include "edge_android.h"

static int GetEdgeCmd(JNIEnv *env, jobject jcmd, n2n_edge_cmd_t* cmd);
static void* EdgeRoutine(void* cmd);
static n2n_edge_cmd_t cmd;
static pthread_t tid = -1;

JNIEXPORT jboolean JNICALL Java_wang_switchy_an2n_N2NService_startEdge(
        JNIEnv *env,
        jobject this,
        jobject jcmd) {

#ifndef NDEBUG
    __android_log_write(LOG_DEBUG, "edge_jni", "in start");
#endif /* #ifndef NDEBUG */
    if (GetEdgeCmd(env, jcmd, &cmd) != 0) {
        goto ERROR;
    }

    int val = fcntl(cmd.vpn_fd, F_GETFL);
    if (val == -1) {
        goto ERROR;
    }
    if ((val & O_NONBLOCK) == O_NONBLOCK) {
        val &= ~O_NONBLOCK;
        val = fcntl(cmd.vpn_fd, F_SETFL, val);
        if (val == -1) {
            goto ERROR;
        }
    }

    if (tid != -1) {
        stop_edge();
        pthread_kill(tid, SIGINT);
        pthread_join(tid, NULL);
        tid = -1;
    }
    int ret = pthread_create(&tid, NULL, EdgeRoutine, &cmd);
    if (ret != 0) {
        tid = -1;
        goto ERROR;
    }

    return JNI_TRUE;

ERROR:
    free(cmd.enc_key);
    free(cmd.enc_key_file);
    cmd.enc_key = NULL;
    cmd.enc_key_file = NULL;
    return JNI_FALSE;
}

JNIEXPORT void JNICALL Java_wang_switchy_an2n_N2NService_stopEdge(
        JNIEnv *env,
        jobject this) {

#ifndef NDEBUG
    __android_log_write(LOG_DEBUG, "edge_jni", "in stop");
#endif /* #ifndef NDEBUG */
    stop_edge();
    pthread_join(tid, NULL);
    tid = -1;
}

/////////////////////////////////////////////////////////////////////////
#ifndef JNI_CHECKNULL
#define JNI_CHECKNULL(p)            do { if (!(p)) return 1;}while(0)
#endif /* JNI_CHECKNULL */

int GetEdgeCmd(JNIEnv *env, jobject jcmd, n2n_edge_cmd_t* cmd)
{
    jclass cls;
    int i, j;

    INIT_EDGE_CMD(*cmd);
    cls = (*env)->GetObjectClass(env, jcmd);
    JNI_CHECKNULL(cls);

    // ipAddr
    {
        jstring jsIpAddr = (*env)->GetObjectField(env, jcmd, (*env)->GetFieldID(env, cls, "ipAddr", "Ljava/lang/String;"));
        JNI_CHECKNULL(jsIpAddr);
        const char* ipAddr = (*env)->GetStringUTFChars(env, jsIpAddr, NULL);
        if (!ipAddr || strlen(ipAddr) == 0) {
            (*env)->ReleaseStringUTFChars(env, jsIpAddr, ipAddr);
            return 1;
        }
        strncpy(cmd->ip_addr, ipAddr, EDGE_CMD_IPSTR_SIZE);
        (*env)->ReleaseStringUTFChars(env, jsIpAddr, ipAddr);
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "ipAddr = %s", cmd->ip_addr);
#endif /* #ifndef NDEBUG */
    }
    // ipNetmask
    {
        jstring jsIpNetmask = (*env)->GetObjectField(env, jcmd, (*env)->GetFieldID(env, cls, "ipNetmask", "Ljava/lang/String;"));
        JNI_CHECKNULL(jsIpNetmask);
        const char* ipNetmask = (*env)->GetStringUTFChars(env, jsIpNetmask, NULL);
        if (!ipNetmask || strlen(ipNetmask) == 0) {
            (*env)->ReleaseStringUTFChars(env, jsIpNetmask, ipNetmask);
            return 1;
        }
        strncpy(cmd->ip_netmask, ipNetmask, EDGE_CMD_IPSTR_SIZE);
        (*env)->ReleaseStringUTFChars(env, jsIpNetmask, ipNetmask);
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "ipNetmask = %s", cmd->ip_netmask);
#endif /* #ifndef NDEBUG */
    }
    // supernodes
    {
        jarray jaSupernodes = (*env)->GetObjectField(env, jcmd, (*env)->GetFieldID(env, cls, "supernodes", "[Ljava/lang/String;"));
        JNI_CHECKNULL(jaSupernodes);
        int len = (*env)->GetArrayLength(env, jaSupernodes);
        if (len <= 0) {
            return 1;
        }
        for (i = 0, j = 0; i < len && i < EDGE_CMD_SUPERNODES_NUM; ++i) {
            const jobject jsNode = (*env)->GetObjectArrayElement(env, jaSupernodes, i);
            if (!jsNode) {
                continue;
            }
            const char* node = (*env)->GetStringUTFChars(env, jsNode, NULL);
            if (!node || strlen(node) == 0) {
                (*env)->ReleaseStringUTFChars(env, jsNode, node);
                continue;
            }
            strncpy(cmd->supernodes[j], node, EDGE_CMD_SN_HOST_SIZE);
            (*env)->ReleaseStringUTFChars(env, jsNode, node);
#ifndef NDEBUG
            __android_log_print(LOG_DEBUG, "edge_jni", "supernodes = %s", cmd->supernodes[j]);
#endif /* #ifndef NDEBUG */
            j++;
        }
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "j = %d", j);
#endif /* #ifndef NDEBUG */
        if (j == 0) {
            return 1;
        }
    }
    // community
    {
        jstring jsCommunity = (*env)->GetObjectField(env, jcmd, (*env)->GetFieldID(env, cls, "community", "Ljava/lang/String;"));
        JNI_CHECKNULL(jsCommunity);
        const char* community = (*env)->GetStringUTFChars(env, jsCommunity, NULL);
        if (!community || strlen(community) == 0) {
            (*env)->ReleaseStringUTFChars(env, jsCommunity, community);
            return 1;
        }
        strncpy(cmd->community, community, N2N_COMMUNITY_SIZE);
        (*env)->ReleaseStringUTFChars(env, jsCommunity, community);
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "community = %s", cmd->community);
#endif /* #ifndef NDEBUG */
    }
    // encKey
    {
        jstring jsEncKey = (*env)->GetObjectField(env, jcmd, (*env)->GetFieldID(env, cls, "encKey", "Ljava/lang/String;"));
        if (jsEncKey) {
            const char* encKey = (*env)->GetStringUTFChars(env, jsEncKey, NULL);
            if (encKey && strlen(encKey) != 0) {
                cmd->enc_key = strdup(encKey);
            }
            (*env)->ReleaseStringUTFChars(env, jsEncKey, encKey);
#ifndef NDEBUG
            __android_log_print(LOG_DEBUG, "edge_jni", "encKey = %s", cmd->enc_key);
#endif /* #ifndef NDEBUG */
        }
    }
    // encKeyFile
    {
        jstring jsEncKeyFile = (*env)->GetObjectField(env, jcmd, (*env)->GetFieldID(env, cls, "encKeyFile", "Ljava/lang/String;"));
        if (jsEncKeyFile) {
            const char* encKeyFile = (*env)->GetStringUTFChars(env, jsEncKeyFile, NULL);
            if (encKeyFile && strlen(encKeyFile) != 0) {
                cmd->enc_key_file = strdup(encKeyFile);
            }
            (*env)->ReleaseStringUTFChars(env, jsEncKeyFile, encKeyFile);
#ifndef NDEBUG
            __android_log_print(LOG_DEBUG, "edge_jni", "encKeyFile = %s", cmd->enc_key_file);
#endif /* #ifndef NDEBUG */
        }
    }
    // macAddr
    {
        jstring jsMacAddr = (*env)->GetObjectField(env, jcmd, (*env)->GetFieldID(env, cls, "macAddr", "Ljava/lang/String;"));
        JNI_CHECKNULL(jsMacAddr);
        const char* macAddr = (*env)->GetStringUTFChars(env, jsMacAddr, NULL);
        if (macAddr && strlen(macAddr) != 0) {
            strncpy(cmd->mac_addr, macAddr, EDGE_CMD_MACNAMSIZ);
        }
        (*env)->ReleaseStringUTFChars(env, jsMacAddr, macAddr);
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "macAddr = %s", cmd->mac_addr);
#endif /* #ifndef NDEBUG */
    }
    // mtu
    {
        jint jiMtu = (*env)->GetIntField(env, jcmd, (*env)->GetFieldID(env, cls, "mtu", "I"));
        if (jiMtu <= 0) {
            return 1;
        }
        cmd->mtu = jiMtu;
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "mtu = %d", cmd->mtu);
#endif /* #ifndef NDEBUG */
    }
    // localIP
    {
        jstring jsLocalIP = (*env)->GetObjectField(env, jcmd, (*env)->GetFieldID(env, cls, "localIP", "Ljava/lang/String;"));
        JNI_CHECKNULL(jsLocalIP);
        const char* localIP = (*env)->GetStringUTFChars(env, jsLocalIP, NULL);
        if (localIP && strlen(localIP) != 0) {
            strncpy(cmd->local_ip, localIP, EDGE_CMD_IPSTR_SIZE);
        }
        (*env)->ReleaseStringUTFChars(env, jsLocalIP, localIP);
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "localIP = %s", cmd->local_ip);
#endif /* #ifndef NDEBUG */
    }
    // holePunchInterval
    {
        jint jiHolePunchInterval = (*env)->GetIntField(env, jcmd, (*env)->GetFieldID(env, cls, "holePunchInterval", "I"));
        if (jiHolePunchInterval <= 0) {
            return 1;
        }
        cmd->holepunch_interval = jiHolePunchInterval;
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "holePunchInterval = %d", cmd->holepunch_interval);
#endif /* #ifndef NDEBUG */
    }
    // reResoveSupernodeIP
    {
        jboolean jbReResoveSupernodeIP= (*env)->GetBooleanField(env, jcmd, (*env)->GetFieldID(env, cls, "reResoveSupernodeIP", "Z"));
        cmd->re_resolve_supernode_ip = jbReResoveSupernodeIP ? 1 : 0;
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "reResoveSupernodeIP = %d", cmd->re_resolve_supernode_ip);
#endif /* #ifndef NDEBUG */
    }
    // localPort
    {
        jint jiLocalPort = (*env)->GetIntField(env, jcmd, (*env)->GetFieldID(env, cls, "localPort", "I"));
        if (jiLocalPort < 0) {
            return 1;
        }
        cmd->local_port = jiLocalPort;
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "localPort = %d", cmd->local_port);
#endif /* #ifndef NDEBUG */
    }
    // reResoveSupernodeIP
    {
        jboolean jbAllowRouting= (*env)->GetBooleanField(env, jcmd, (*env)->GetFieldID(env, cls, "allowRouting", "Z"));
        cmd->allow_routing = jbAllowRouting ? 1 : 0;
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "allowRouting = %d", cmd->allow_routing);
#endif /* #ifndef NDEBUG */
    }
    // dropMuticast
    {
        jboolean jbDropMuticast= (*env)->GetBooleanField(env, jcmd, (*env)->GetFieldID(env, cls, "dropMuticast", "Z"));
        cmd->drop_multicast = jbDropMuticast ? 1 : 0;
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "dropMuticast = %d", cmd->drop_multicast);
#endif /* #ifndef NDEBUG */
    }
    // traceLevel
    {
        jint jiTraceLevel = (*env)->GetIntField(env, jcmd, (*env)->GetFieldID(env, cls, "traceLevel", "I"));
        cmd->trace_vlevel = jiTraceLevel;
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "traceLevel = %d", cmd->trace_vlevel);
#endif /* #ifndef NDEBUG */
    }
    // vpnFd
    {
        jint jiVpnFd = (*env)->GetIntField(env, jcmd, (*env)->GetFieldID(env, cls, "vpnFd", "I"));
        if (jiVpnFd < 0) {
            return 1;
        }
        cmd->vpn_fd = jiVpnFd;
#ifndef NDEBUG
        __android_log_print(LOG_DEBUG, "edge_jni", "vpnFd = %d", cmd->vpn_fd);
#endif /* #ifndef NDEBUG */
    }

    return 0;
}

void* EdgeRoutine(void* cmd)
{
    n2n_edge_cmd_t* c = cmd;
    int ret = start_edge(c);
    free(c->enc_key);
    free(c->enc_key_file);
    c->enc_key = NULL;
    c->enc_key_file = NULL;
    return (void*)ret;
}
