# SentrySDK 📱🏷️ - Powerful functionality in a few lines of code
### Backed with CoreNFC

## Aims
Provide an easy way for iOS developers to access biometric enrollment and other functionality on Sentry java cards via NFC Tags.

## Version
Unreleased

## Environment

### Xcode Local
Tested on | Latest | Compatible
--------- | ------ | ----------
iOS       | 16     | >= 16

* Apple Watch is not supported. iPad / Mac is compatible with CoreNFC but there is no hardware to support this feature. *

### Xcode Cloud ☁️
Compatible ✅

*Xcode Cloud requires Apple Developer Program membership.*

## Requirements
This is meant for use with the Java Card technology from Sentry Enterprises. As such, this library requires the following in order to utilize its full functionality:

1. NFC reader entitlements in the application capabilities and in the application's bundle identifier (see below).
2. Several additions to the application's ```Custom iOS Target Properties``` (see below).
3. A Java Card from Sentry Enterprises that includes the IDEX Enroll applet installed on the card.


## Guide

Note about
PIN length, digit range
5 second timeout waiting for fingerprints that cannot be set
verbose debug output
NFC reader entitlements (in app and in bundle id)
* NFC Privacy plist entry
Enroll applet AID in plist

requires an java card with an ISO7816 compliant NFC tag

###  IMPORTANT - ABOUT THE PIN
While users are never meant to see or enter a PIN, the IDEX Enroll applet requires a PIN verification before it processes some commands. This PIN is usually set during initialization of the Java Card itself, and can vary depending on how the card is initialized. This usually happens through a script that is run using JCShell. 

The PIN is required internally by the SentrySDK and is set in the constructor. This PIN is checked when first communicating with the Enroll applet on the card. The application implementing this library must take care to ensure that the PIN provided to the SentrySDK matches the PIN on the card. Otherwise, calls to initialize the Enroll applet will fail with ```0x63CX``` errors, and eventually the card will need to be reset after four (4) attempts. 

If no PIN is set, this library sets the PIN to the value provided to the SentrySDK in its constructor. The PIN MUST be 4-6 characters in length. Less than four (4) characters causes the app to throw an error. Any characters after the 6th are ignored.




## Preparation
1. Add NFC Tag Reading to your App ID.

![image](https://github.com/SentryEnterprises/SentrySDK/assets/166414810/a62ef001-5a09-43d5-ada3-c38b8dd8acc7)

2. Add to your project via Package Manager.

3. Add ```Near Field Communication Tag Reading``` to your project's capabilities.
![image](https://github.com/SentryEnterprises/SentrySDK/assets/166414810/7e82de27-81bb-4c19-8400-25048b6acc8f)

4. Add NFC Privacy under ```Custom iOS Target Properties``` (i.e. the ```Info``` tab on the target settings).
![image](https://github.com/SentryEnterprises/SentrySDK/assets/166414810/9e840352-1fad-4903-a90a-7cb1d52344f7)




## Basic Usage

1. Import the SentrySDK into your unit.
```swift
import SentrySDK
```

2. Add ObservedObject before ```body``` or any ```some View```.

### Read
```swift
@ObservedObject var NFCR = NFCReader()
```

### Write
```swift
@ObservedObject var NFCW = NFCWriter()
```

### Functions
```swift
func read() {
    NFCR.read()
}
func write() {
    NFCW.msg = NFCR.msg
    NFCW.write()
}
```

## Demo
Path: `./Demo` (Xcode Project in SwiftUI)

## License
MIT
