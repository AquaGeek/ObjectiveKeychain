ObjectiveKeychain is an Objective-C wrapper around Apple's Keychain Services for iOS. It allows you to easily save and retrieve items from the system's keychain.

## Status ##

Generic and Internet passwords are mostly functional. Better support for finding existing items needs to be added, and key/certificate support still needs to be added.

## Usage ##
It's pretty simple to use:

    OKInternetPassword *password = [[OKInternetPassword alloc] initWithLabel:@"My Internet Password"
                                                                 accessGroup:nil];
    password.account = @"my_username";
    password.password = @"MySecr3tP@ssword";
    password.server = @"www.apple.com";
    password.protocol = kNetworkProtocolFTP;
    [password writeToKeychain];
