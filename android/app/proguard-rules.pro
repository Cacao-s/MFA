# The generated bindings reach the native library through JNA, which finds
# everything by name at runtime. R8 cannot see those references, so without
# this the release build strips the classes it needs and fails on first call.
-keep class com.zeyanlin.mfa.core.** { *; }
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }
-dontwarn java.awt.**
