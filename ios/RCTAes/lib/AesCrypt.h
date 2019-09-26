//
//  AesCrypt.h
//
//  Created by tectiv3 on 10/02/17.
//  Copyright © 2017 tectiv3. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AesCrypt : NSObject
+ (NSString *) encrypt: (NSString *)clearText  key: (NSString *)key iv: (NSString *)iv useDeprecatedHex: (BOOL)useDeprecatedHex;
+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key iv: (NSString *)iv useDeprecatedHex: (BOOL)useDeprecatedHex;
+ (NSData *) pbkdf2:(NSString *)password salt: (NSString *)salt cost: (NSInteger)cost length: (NSInteger)length;
+ (NSData *) hmac256: (NSString *)input key: (NSString *)key;
+ (NSData *) sha1: (NSString *)input;
+ (NSData *) sha256: (NSString *)input;
+ (NSData *) sha512: (NSString *)input;
+ (NSString *) toHex: (NSData *)nsdata;
+ (NSString *) fromHexDeprecated: (NSData *)nsdata;
+ (NSString *) toHexDeprecated: (NSData *)nsdata;
+ (NSString *) randomUuid;
+ (NSData *) randomKey: (NSInteger)length;
@end
