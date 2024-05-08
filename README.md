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

5. Add ```ISO7816 application identifiers for NFC Tag Reader Session``` to the application's ```Information Property List``` and add one item to this array with the following value: 494445585F4C5F0101
![image](https://github.com/SentryEnterprises/SentrySDK/assets/166414810/1b107821-3df1-4cba-8db6-57f145fed9ba)



## Basic Usage

1. Import the SentrySDK into your unit.
```swift
import SentrySDK
```

2. Instantiate the ```SentrySDK``` using the PIN set on the card.
```swift
let sentrySDK = SentrySDK(pin: [1, 2, 3, 4])
```

3. Call the desire function.
```swift
let status = try await sentrySDK.getEnrollmentStatus()
```

## Demo
[See the SentryBiometricEnrollAndVerify repository](https://github.com/SentryEnterprises/SentryBiometricEnrollAndVerify)

## License
MIT
