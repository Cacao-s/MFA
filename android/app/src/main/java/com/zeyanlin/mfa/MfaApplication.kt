package com.zeyanlin.mfa

import android.app.Application

/**
 * Nothing to set up at launch: there is no analytics SDK, no crash reporter and
 * no network client to warm. The class exists so the manifest can name it and
 * so there is an obvious place to refuse to add one.
 */
class MfaApplication : Application()
