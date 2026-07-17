-keepclassmembers class dev.kathttp3.internal.NativeBridge { native <methods>; }
-keep class dev.kathttp3.internal.NativeCallback { *; }

# kathttp3 resolves DNS through JNI. These types and member names are looked up
# from JNI_OnLoad/native code, so R8 cannot infer that ResolvedAddress is used.
-keep interface dev.kathttp3.DnsResolver { *; }
-keep class dev.kathttp3.ResolvedAddress { *; }
