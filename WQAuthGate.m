#import "WQAuthGate.h"
#import "WQTheme.h"
#import "WQUI.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <math.h>

static NSString *const kWQAuthRememberKey = @"WQKeyAuthRememberLicense";
static NSString *const kWQAuthLicenseService = @"cz.kolbi.wqfiles.keyauth.license";
static NSString *const kWQAuthLicenseAccount = @"license";
static NSString *const kWQAuthHardwareIDService = @"cz.kolbi.wqfiles.keyauth.hwid";
static NSString *const kWQAuthHardwareIDAccount = @"device-id";
static NSString *const kWQAuthConfirmationService = @"cz.kolbi.wqfiles.keyauth.confirmation";
static NSString *const kWQAuthConfirmationAccount = @"validated-license";
static NSString *const kWQAuthRuntimeSignatureKey = @"WQKeyAuthRuntimeSignature";
static NSString *const kWQAuthValidatedKey = @"WQKeyAuthLicenseValidated";
static NSString *const kWQAuthStatusKey = @"WQKeyAuthLicenseStatus";
static NSString *const kWQAuthMessageKey = @"WQKeyAuthLicenseMessage";
static NSString *const kWQAuthExpiryKey = @"WQKeyAuthLicenseExpiry";
static NSString *const kWQAuthBaseURL = @"https://keyauth.win/api/1.2/";
static const NSTimeInterval kWQAuthRecentValidationAge = 24 * 60 * 60;

typedef void (^WQAuthCompletion)(BOOL valid, NSString *message, BOOL definitiveFailure);

static NSString *wq_auth_config(NSString *key)
{
    id value = NSBundle.mainBundle.infoDictionary[key];
    return [value isKindOfClass:NSString.class] ? value : @"";
}

static NSDate *wq_auth_expiry(id value);
static NSDate *wq_auth_timeleft(id value);
static NSDictionary *wq_auth_confirmation(void);
static void wq_auth_ensure_runtime_state(void);
static BOOL wq_auth_should_force_logout(void);

static NSString *wq_auth_runtime_signature(void)
{
    NSString *material = [@[kWQAuthBaseURL, wq_auth_config(@"WQKeyAuthAppName"),
                            wq_auth_config(@"WQKeyAuthOwnerID"), wq_auth_config(@"WQKeyAuthSecret")]
                          componentsJoinedByString:@"|"];
    NSData *data = [material dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < sizeof(digest); i++) [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

static void wq_auth_delete_confirmation(void)
{
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kWQAuthConfirmationService,
        (__bridge id)kSecAttrAccount: kWQAuthConfirmationAccount,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

static BOOL wq_auth_is_configured(void)
{
    wq_auth_ensure_runtime_state();
    return wq_auth_config(@"WQKeyAuthAppName").length &&
        wq_auth_config(@"WQKeyAuthOwnerID").length && wq_auth_config(@"WQKeyAuthSecret").length;
}

static NSString *wq_auth_keychain_hardware_id(void)
{
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kWQAuthHardwareIDService,
        (__bridge id)kSecAttrAccount: kWQAuthHardwareIDAccount,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef result = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)query, &result) != errSecSuccess || !result) return nil;
    NSData *data = CFBridgingRelease(result);
    NSString *saved = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return [[[NSUUID alloc] initWithUUIDString:saved] UUIDString];
}

static BOOL wq_auth_store_keychain_hardware_id(NSString *identifier)
{
    NSData *data = [identifier dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kWQAuthHardwareIDService,
        (__bridge id)kSecAttrAccount: kWQAuthHardwareIDAccount,
    };
    NSDictionary *attributes = @{
        (__bridge id)kSecValueData: data,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    };
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
    if (status == errSecItemNotFound) {
        NSMutableDictionary *item = [query mutableCopy];
        [item addEntriesFromDictionary:attributes];
        status = SecItemAdd((__bridge CFDictionaryRef)item, NULL);
    }
    return status == errSecSuccess;
}

static NSString *wq_auth_hardware_id(void)
{
    static NSObject *lock;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ lock = [NSObject new]; });
    @synchronized (lock) {
        static NSString *hardwareID;
        if (hardwareID.length) return hardwareID;

        hardwareID = wq_auth_keychain_hardware_id();
        if (!hardwareID.length) {
            NSString *confirmed = wq_auth_confirmation()[@"hardwareID"];
            hardwareID = [[[NSUUID alloc] initWithUUIDString:confirmed] UUIDString];
        }
        NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
        if (!hardwareID.length) hardwareID = UIDevice.currentDevice.identifierForVendor.UUIDString;
        if (!hardwareID.length) {
            NSString *legacy = [defaults stringForKey:@"WQKeyAuthHardwareID"];
            hardwareID = [[[NSUUID alloc] initWithUUIDString:legacy] UUIDString];
        }
        if (!hardwareID.length) hardwareID = NSUUID.UUID.UUIDString;
        if (!wq_auth_store_keychain_hardware_id(hardwareID))
            [defaults setObject:hardwareID forKey:@"WQKeyAuthHardwareID"];
        else
            [defaults removeObjectForKey:@"WQKeyAuthHardwareID"];
        return hardwareID;
    }
}

static NSString *wq_auth_saved_license(void)
{
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kWQAuthLicenseService,
        (__bridge id)kSecAttrAccount: kWQAuthLicenseAccount,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || !result) return @"";
    NSData *data = CFBridgingRelease(result);
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
}

static BOOL wq_auth_store_license(NSString *license)
{
    NSData *data = [license dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kWQAuthLicenseService,
        (__bridge id)kSecAttrAccount: kWQAuthLicenseAccount,
    };
    NSDictionary *attributes = @{
        (__bridge id)kSecValueData: data,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    };
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
    if (status == errSecItemNotFound) {
        NSMutableDictionary *item = [query mutableCopy];
        [item addEntriesFromDictionary:attributes];
        status = SecItemAdd((__bridge CFDictionaryRef)item, NULL);
    }
    return status == errSecSuccess;
}

static void wq_auth_delete_license(void)
{
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kWQAuthLicenseService,
        (__bridge id)kSecAttrAccount: kWQAuthLicenseAccount,
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

static NSDictionary *wq_auth_confirmation(void)
{
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kWQAuthConfirmationService,
        (__bridge id)kSecAttrAccount: kWQAuthConfirmationAccount,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef result = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)query, &result) != errSecSuccess || !result) return nil;
    NSData *data = CFBridgingRelease(result);
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [object isKindOfClass:NSDictionary.class] ? object : nil;
}

static void wq_auth_store_confirmation(NSString *license)
{
    NSDictionary *confirmation = @{
        @"license": license,
        @"runtimeSignature": wq_auth_runtime_signature(),
        @"hardwareID": wq_auth_hardware_id(),
        @"validatedAt": @(NSDate.date.timeIntervalSince1970),
    };
    NSData *data = [NSJSONSerialization dataWithJSONObject:confirmation options:0 error:nil];
    if (!data) return;
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kWQAuthConfirmationService,
        (__bridge id)kSecAttrAccount: kWQAuthConfirmationAccount,
    };
    NSDictionary *attributes = @{
        (__bridge id)kSecValueData: data,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    };
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
    if (status == errSecItemNotFound) {
        NSMutableDictionary *item = [query mutableCopy];
        [item addEntriesFromDictionary:attributes];
        SecItemAdd((__bridge CFDictionaryRef)item, NULL);
    }
}

static void wq_auth_clear_session(void)
{
    wq_auth_delete_license();
    wq_auth_delete_confirmation();
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    [defaults setBool:NO forKey:kWQAuthRememberKey];
    [defaults removeObjectForKey:kWQAuthValidatedKey];
    [defaults removeObjectForKey:kWQAuthStatusKey];
    [defaults removeObjectForKey:kWQAuthMessageKey];
    [defaults removeObjectForKey:kWQAuthExpiryKey];
}

static void wq_auth_ensure_runtime_state(void)
{
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSString *current = wq_auth_runtime_signature();
    NSString *previous = [defaults stringForKey:kWQAuthRuntimeSignatureKey];
    if (!previous) {
        [defaults setObject:current forKey:kWQAuthRuntimeSignatureKey];
    } else if (![previous isEqualToString:current]) {
        [defaults setObject:current forKey:kWQAuthRuntimeSignatureKey];
        wq_auth_clear_session();
    }
}

static BOOL wq_auth_session_is_valid(NSString *license)
{
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSDictionary *confirmation = wq_auth_confirmation();
    NSString *saved = wq_auth_saved_license();
    double validatedAt = [confirmation[@"validatedAt"] doubleValue];
    double now = NSDate.date.timeIntervalSince1970;
    if (![defaults boolForKey:kWQAuthValidatedKey] || ![saved isEqualToString:license] ||
        ![confirmation[@"license"] isEqualToString:license] ||
        ![confirmation[@"runtimeSignature"] isEqualToString:wq_auth_runtime_signature()] ||
        ![confirmation[@"hardwareID"] isEqualToString:wq_auth_hardware_id()] ||
        validatedAt <= 0 || now < validatedAt || now - validatedAt > kWQAuthRecentValidationAge ||
        wq_auth_should_force_logout()) return NO;
    NSDate *expiry = wq_auth_expiry([defaults stringForKey:kWQAuthExpiryKey]);
    return !expiry || expiry.timeIntervalSinceNow > 0;
}

static BOOL wq_auth_should_force_logout(void)
{
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    if (![[defaults stringForKey:kWQAuthRuntimeSignatureKey] isEqualToString:wq_auth_runtime_signature()]) return YES;
    NSString *status = [defaults stringForKey:kWQAuthStatusKey].lowercaseString ?: @"";
    for (NSString *invalid in @[@"expired", @"expiration", @"invalid", @"revoked", @"banned", @"used", @"hwid"]) {
        if ([status containsString:invalid]) return YES;
    }
    NSDate *expiry = wq_auth_expiry([defaults stringForKey:kWQAuthExpiryKey]);
    return expiry && expiry.timeIntervalSinceNow <= 0;
}

static NSString *wq_auth_expiry_text(NSDate *date)
{
    if (!date) return @"";
    NSISO8601DateFormatter *formatter = [NSISO8601DateFormatter new];
    formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime | NSISO8601DateFormatWithFractionalSeconds;
    return [formatter stringFromDate:date];
}

static void wq_auth_persist_result(NSString *license, BOOL valid, NSString *status, NSDate *expiry)
{
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    wq_auth_store_license(license);
    [defaults setBool:valid forKey:kWQAuthValidatedKey];
    [defaults setObject:status ?: @"unknown" forKey:kWQAuthStatusKey];
    [defaults setObject:wq_auth_expiry_text(expiry) forKey:kWQAuthExpiryKey];
    if (valid) wq_auth_store_confirmation(license);
    else wq_auth_delete_confirmation();
}

static NSDate *wq_auth_response_expiry(NSDictionary *json, NSString *license, NSString *responseText)
{
    NSDictionary *info = [json[@"info"] isKindOfClass:NSDictionary.class] ? json[@"info"] : nil;
    NSArray *subscriptions = [info[@"subscriptions"] isKindOfClass:NSArray.class] ? info[@"subscriptions"] : nil;
    NSDictionary *first = [subscriptions.firstObject isKindOfClass:NSDictionary.class] ? subscriptions.firstObject : nil;
    for (NSString *key in @[@"expiry", @"expires", @"expires_at", @"expiration", @"expirationDate", @"expiration_date", @"expiresAt"]) {
        NSDate *date = wq_auth_expiry(json[key]);
        if (date) return date;
        date = wq_auth_expiry(info[key]);
        if (date) return date;
        date = wq_auth_expiry(first[key]);
        if (date) return date;
    }
    NSDate *timeleft = wq_auth_timeleft(first[@"timeleft"]);
    if (timeleft) return timeleft;

    NSString *upperLicense = license.uppercaseString;
    double duration = 0;
    NSString *unit = @"";
    if ([upperLicense containsString:@"MES"] || [upperLicense containsString:@"MONTH"]) { duration = 1; unit = @"month"; }
    else if ([upperLicense containsString:@"SEM"] || [upperLicense containsString:@"WEEK"]) { duration = 1; unit = @"week"; }
    else if ([upperLicense containsString:@"DIA"] || [upperLicense containsString:@"DAY"]) { duration = 1; unit = @"day"; }

    NSString *durationText = responseText ?: @"";
    NSRegularExpression *expression = [NSRegularExpression regularExpressionWithPattern:@"(\\d+(?:\\.\\d+)?)\\s*(days?|d|weeks?|w|months?|m|hours?|h|horas|dias|semanas|meses)" options:NSRegularExpressionCaseInsensitive error:nil];
    NSTextCheckingResult *match = [expression firstMatchInString:durationText options:0 range:NSMakeRange(0, durationText.length)];
    if (!match) {
        for (id value in json.allValues) {
            if (![value isKindOfClass:NSString.class]) continue;
            NSString *candidate = value;
            match = [expression firstMatchInString:candidate options:0 range:NSMakeRange(0, candidate.length)];
            if (match) { durationText = candidate; break; }
        }
    }
    if (match.numberOfRanges == 3) {
        NSString *amount = [durationText substringWithRange:[match rangeAtIndex:1]];
        NSString *unitText = [[durationText substringWithRange:[match rangeAtIndex:2]] lowercaseString];
        duration = amount.doubleValue;
        unit = ([unitText hasPrefix:@"m"] || [unitText containsString:@"mes"]) ? @"month"
             : ([unitText hasPrefix:@"w"] || [unitText containsString:@"sem"]) ? @"week"
             : ([unitText hasPrefix:@"h"] || [unitText containsString:@"hora"]) ? @"hour" : @"day";
    }
    if (duration <= 0 || !unit.length) return nil;

    NSDate *base = NSDate.date;
    for (NSString *key in @[@"created", @"created_at", @"creation", @"creation_date", @"date", @"used", @"used_at", @"lastlogin", @"last_login"]) {
        NSDate *candidate = wq_auth_expiry(json[key]);
        if (!candidate) candidate = wq_auth_expiry(info[key]);
        if (candidate) { base = candidate; break; }
    }
    if ([unit isEqualToString:@"month"]) {
        NSInteger wholeMonths = (NSInteger)floor(duration);
        NSDate *monthDate = wholeMonths > 0
            ? [[NSCalendar currentCalendar] dateByAddingUnit:NSCalendarUnitMonth value:wholeMonths toDate:base options:0] : base;
        return [monthDate dateByAddingTimeInterval:(duration - wholeMonths) * 30.0 * 86400.0];
    }
    double seconds = [unit isEqualToString:@"week"] ? 7 * 86400.0 : [unit isEqualToString:@"hour"] ? 3600.0 : 86400.0;
    return [base dateByAddingTimeInterval:duration * seconds];
}

static NSURL *wq_auth_url(NSArray<NSURLQueryItem *> *items)
{
    NSURLComponents *components = [NSURLComponents componentsWithString:kWQAuthBaseURL];
    if (!components) return nil;
    components.queryItems = items;
    return components.URL;
}

static NSDate *wq_auth_expiry(id value)
{
    if ([value isKindOfClass:NSNumber.class]) {
        double number = [value doubleValue];
        if (number > 1000000000000.0) return [NSDate dateWithTimeIntervalSince1970:number / 1000.0];
        if (number > 1500000000.0) return [NSDate dateWithTimeIntervalSince1970:number];
        return [NSDate dateWithTimeIntervalSinceNow:number > 0 && number <= 31 ? number * 86400.0 : number];
    }
    if (![value isKindOfClass:NSString.class] || ![value length]) return nil;
    NSString *text = [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSScanner *scanner = [NSScanner scannerWithString:text];
    double number = 0;
    if ([scanner scanDouble:&number] && scanner.isAtEnd) return wq_auth_expiry(@(number));
    NSISO8601DateFormatter *iso = [NSISO8601DateFormatter new];
    iso.formatOptions = NSISO8601DateFormatWithInternetDateTime | NSISO8601DateFormatWithFractionalSeconds;
    NSDate *date = [iso dateFromString:text];
    if (!date) {
        iso.formatOptions = NSISO8601DateFormatWithInternetDateTime;
        date = [iso dateFromString:text];
    }
    if (date) return date;
    NSDateFormatter *formatter = [NSDateFormatter new];
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
    for (NSString *format in @[@"yyyy-MM-dd HH:mm:ss", @"yyyy-MM-dd", @"dd/MM/yyyy", @"dd-MM-yyyy"]) {
        formatter.dateFormat = format;
        date = [formatter dateFromString:text];
        if (date) return date;
    }
    return nil;
}

static NSDate *wq_auth_timeleft(id value)
{
    double seconds = 0;
    if ([value isKindOfClass:NSNumber.class]) {
        seconds = [value doubleValue];
    } else if ([value isKindOfClass:NSString.class]) {
        NSScanner *scanner = [NSScanner scannerWithString:value];
        if (![scanner scanDouble:&seconds] || !scanner.isAtEnd) return nil;
    } else {
        return nil;
    }
    return isfinite(seconds) ? [NSDate dateWithTimeIntervalSinceNow:seconds] : nil;
}

static NSDictionary *wq_auth_json(NSData *data)
{
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [object isKindOfClass:NSDictionary.class] ? object : nil;
}

static NSString *wq_auth_response_preview(NSData *data, NSArray<NSString *> *sensitiveValues)
{
    NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!body) return @"(el cuerpo no es UTF-8)";
    NSCharacterSet *unreserved = [NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"];
    for (NSString *sensitive in sensitiveValues) {
        if (!sensitive.length) continue;
        NSMutableSet<NSString *> *variants = [NSMutableSet setWithObjects:sensitive, sensitive.lowercaseString,
            sensitive.uppercaseString, nil];
        NSString *encoded = [sensitive stringByAddingPercentEncodingWithAllowedCharacters:unreserved];
        if (encoded.length) {
            [variants addObject:encoded];
            [variants addObject:encoded.lowercaseString];
            [variants addObject:encoded.uppercaseString];
        }
        for (NSString *variant in variants)
            body = [body stringByReplacingOccurrencesOfString:variant withString:@"[oculto]" options:NSCaseInsensitiveSearch range:NSMakeRange(0, body.length)];
    }
    NSArray<NSString *> *lines = [body componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet];
    body = [[lines componentsJoinedByString:@" "] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSMutableString *safe = [NSMutableString new];
    for (NSUInteger i = 0; i < body.length; i++) {
        unichar c = [body characterAtIndex:i];
        unichar safeCharacter = [[NSCharacterSet controlCharacterSet] characterIsMember:c] ? (unichar)' ' : c;
        [safe appendFormat:@"%C", safeCharacter];
        if (safe.length >= 180) break;
    }
    if (body.length > safe.length) [safe appendString:@"…"];
    return safe.length ? safe : @"(vacío)";
}

static NSString *wq_auth_string(id value)
{
    if ([value isKindOfClass:NSString.class]) return value;
    if ([value isKindOfClass:NSNumber.class]) return [value stringValue];
    return @"";
}

static BOOL wq_auth_boolean(id value, BOOL *recognized)
{
    if ([value isKindOfClass:NSNumber.class]) {
        if (recognized) *recognized = YES;
        return [value boolValue];
    }
    if ([value isKindOfClass:NSString.class]) {
        NSString *text = [[value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] lowercaseString];
        if ([text isEqualToString:@"true"] || [text isEqualToString:@"1"] || [text isEqualToString:@"yes"]) {
            if (recognized) *recognized = YES;
            return YES;
        }
        if ([text isEqualToString:@"false"] || [text isEqualToString:@"0"] || [text isEqualToString:@"no"]) {
            if (recognized) *recognized = YES;
            return NO;
        }
    }
    if (recognized) *recognized = NO;
    return NO;
}

static NSString *wq_auth_response_keys(NSDictionary *response)
{
    NSArray<NSString *> *keys = [[response allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSString *summary = [keys componentsJoinedByString:@", "];
    if (summary.length > 160) summary = [[summary substringToIndex:160] stringByAppendingString:@"…"];
    return summary.length ? summary : @"(ninguno)";
}

static void wq_auth_validate(NSString *license, WQAuthCompletion completion)
{
    wq_auth_ensure_runtime_state();
    NSString *appName = wq_auth_config(@"WQKeyAuthAppName");
    NSString *ownerID = wq_auth_config(@"WQKeyAuthOwnerID");
    NSString *secret = wq_auth_config(@"WQKeyAuthSecret");
    if (!appName.length || !ownerID.length || !secret.length) {
        completion(NO, @"KeyAuth no está configurado para esta compilación.", YES);
        return;
    }
    NSString *cleanLicense = [license stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!cleanLicense.length) {
        completion(NO, @"Ingresa tu licencia.", YES);
        return;
    }

    NSURLSession *session = NSURLSession.sharedSession;
    NSArray<NSURLQueryItem *> *initItems = @[
        [NSURLQueryItem queryItemWithName:@"type" value:@"init"],
        [NSURLQueryItem queryItemWithName:@"name" value:appName],
        [NSURLQueryItem queryItemWithName:@"ownerid" value:ownerID],
        [NSURLQueryItem queryItemWithName:@"secret" value:secret],
        [NSURLQueryItem queryItemWithName:@"ver" value:@"1.0"],
    ];
    NSURL *initURL = wq_auth_url(initItems);
    if (!initURL) {
        completion(NO, @"La configuración de KeyAuth no es válida.", YES);
        return;
    }
    NSMutableURLRequest *initRequest = [NSMutableURLRequest requestWithURL:initURL];
    initRequest.HTTPMethod = @"GET";
    initRequest.timeoutInterval = 20;
    [initRequest setValue:@"KeyAuth" forHTTPHeaderField:@"User-Agent"];
    [[session dataTaskWithRequest:initRequest completionHandler:^(NSData *initData, NSURLResponse *initResponse, NSError *initError) {
        NSDictionary *initJSON = initData ? wq_auth_json(initData) : nil;
        NSHTTPURLResponse *httpInit = [initResponse isKindOfClass:NSHTTPURLResponse.class] ? (NSHTTPURLResponse *)initResponse : nil;
        NSString *sessionID = [initJSON[@"sessionid"] isKindOfClass:NSString.class] ? initJSON[@"sessionid"] : nil;
        if (initError) {
            completion(NO, [NSString stringWithFormat:@"No se pudo conectar con KeyAuth: %@", initError.localizedDescription], NO);
            return;
        }
        if (!httpInit) {
            completion(NO, @"KeyAuth devolvió una respuesta que no es HTTP.", NO);
            return;
        }
        if (httpInit.statusCode < 200 || httpInit.statusCode >= 300) {
            completion(NO, [NSString stringWithFormat:@"KeyAuth respondió con HTTP %ld al iniciar sesión.", (long)httpInit.statusCode], NO);
            return;
        }
        if (!initJSON) {
            NSString *contentType = [httpInit.allHeaderFields[@"Content-Type"] isKindOfClass:NSString.class]
                ? httpInit.allHeaderFields[@"Content-Type"] : @"desconocido";
            NSString *preview = wq_auth_response_preview(initData ?: [NSData data], @[secret, appName, ownerID]);
            completion(NO, [NSString stringWithFormat:@"KeyAuth respondió HTTP %ld con contenido %@, no con un objeto JSON. Respuesta: %@",
                            (long)httpInit.statusCode, contentType, preview], NO);
            return;
        }
        id rawSuccess = initJSON[@"success"];
        if (!rawSuccess || rawSuccess == NSNull.null) {
            completion(NO, [NSString stringWithFormat:@"El JSON de inicio de KeyAuth no contiene 'success'. Campos recibidos: %@.",
                            wq_auth_response_keys(initJSON)], NO);
            return;
        }
        BOOL successRecognized = NO;
        BOOL initSuccess = wq_auth_boolean(rawSuccess, &successRecognized);
        if (!successRecognized) {
            completion(NO, [NSString stringWithFormat:@"El campo 'success' de KeyAuth tiene un formato no reconocido (%@). Campos recibidos: %@.",
                            NSStringFromClass([rawSuccess class]), wq_auth_response_keys(initJSON)], NO);
            return;
        }
        if (!initSuccess) {
            NSString *serverMessage = [initJSON[@"message"] isKindOfClass:NSString.class] ? initJSON[@"message"] : @"KeyAuth rechazó la configuración de WQ.";
            if (serverMessage.length > 180) serverMessage = [[serverMessage substringToIndex:180] stringByAppendingString:@"…"];
            completion(NO, [NSString stringWithFormat:@"KeyAuth: %@", serverMessage], YES);
            return;
        }
        if (!sessionID.length) {
            completion(NO, @"KeyAuth confirmó el inicio, pero no devolvió un session ID.", NO);
            return;
        }
        NSArray<NSURLQueryItem *> *licenseItems = @[
            [NSURLQueryItem queryItemWithName:@"type" value:@"license"],
            [NSURLQueryItem queryItemWithName:@"key" value:cleanLicense],
            [NSURLQueryItem queryItemWithName:@"hwid" value:wq_auth_hardware_id()],
            [NSURLQueryItem queryItemWithName:@"sessionid" value:sessionID],
            [NSURLQueryItem queryItemWithName:@"name" value:appName],
            [NSURLQueryItem queryItemWithName:@"ownerid" value:ownerID],
        ];
        NSURL *licenseURL = wq_auth_url(licenseItems);
        if (!licenseURL) {
            completion(NO, @"La configuración de KeyAuth no es válida.", YES);
            return;
        }
        NSMutableURLRequest *licenseRequest = [NSMutableURLRequest requestWithURL:licenseURL];
        licenseRequest.HTTPMethod = @"GET";
        licenseRequest.timeoutInterval = 20;
        [licenseRequest setValue:@"KeyAuth" forHTTPHeaderField:@"User-Agent"];
        [[session dataTaskWithRequest:licenseRequest completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            NSDictionary *json = data ? wq_auth_json(data) : nil;
            NSHTTPURLResponse *http = [response isKindOfClass:NSHTTPURLResponse.class] ? (NSHTTPURLResponse *)response : nil;
            if (error) {
                completion(NO, [NSString stringWithFormat:@"No se pudo conectar con KeyAuth: %@", error.localizedDescription], NO);
                return;
            }
            if (!http) {
                completion(NO, @"KeyAuth devolvió una respuesta de licencia que no es HTTP.", NO);
                return;
            }
            if (http.statusCode < 200 || http.statusCode >= 300) {
                completion(NO, [NSString stringWithFormat:@"KeyAuth respondió con HTTP %ld al validar la licencia.", (long)http.statusCode], NO);
                return;
            }
            if (!json) {
                NSString *contentType = [http.allHeaderFields[@"Content-Type"] isKindOfClass:NSString.class]
                    ? http.allHeaderFields[@"Content-Type"] : @"desconocido";
                NSString *preview = wq_auth_response_preview(data ?: [NSData data], @[cleanLicense, secret, appName, ownerID]);
                completion(NO, [NSString stringWithFormat:@"La respuesta de licencia no es JSON (%@). Respuesta: %@", contentType, preview], NO);
                return;
            }
            id rawSuccess = json[@"success"];
            if (!rawSuccess || rawSuccess == NSNull.null) {
                completion(NO, [NSString stringWithFormat:@"El JSON de licencia no contiene 'success'. Campos recibidos: %@.",
                                wq_auth_response_keys(json)], NO);
                return;
            }
            BOOL successRecognized = NO;
            BOOL success = wq_auth_boolean(rawSuccess, &successRecognized);
            if (!successRecognized) {
                completion(NO, [NSString stringWithFormat:@"El campo 'success' de licencia tiene formato no reconocido (%@). Campos recibidos: %@.",
                                NSStringFromClass([rawSuccess class]), wq_auth_response_keys(json)], NO);
                return;
            }
            NSString *status = [[@[wq_auth_string(json[@"status"]), wq_auth_string(json[@"result"]),
                                   wq_auth_string(json[@"expiry"])] componentsJoinedByString:@" "] lowercaseString];
            if (!success) {
                NSString *message = [json[@"message"] isKindOfClass:NSString.class] ? json[@"message"] : @"Licencia inválida o expirada.";
                wq_auth_persist_result(cleanLicense, NO, status.length ? status : @"invalid", nil);
                completion(NO, message, YES);
                return;
            }
            NSDictionary *info = [json[@"info"] isKindOfClass:NSDictionary.class] ? json[@"info"] : nil;
            id rawHWID = json[@"hwid"] ?: info[@"hwid"];
            NSString *serverHWID = [rawHWID isKindOfClass:NSString.class] ? rawHWID : @"";
            if (serverHWID.length && ![serverHWID isEqualToString:wq_auth_hardware_id()]) {
                wq_auth_persist_result(cleanLicense, NO, @"hwid_mismatch", nil);
                completion(NO, @"La licencia está vinculada a otro dispositivo.", YES);
                return;
            }
            for (NSString *word in @[@"expired", @"expiration", @"invalid", @"not valid", @"not found", @"error", @"failed", @"denied", @"revoked", @"banned", @"already used", @"already in use", @"used"]) {
                if ([status containsString:word]) {
                    wq_auth_persist_result(cleanLicense, NO, status, nil);
                    completion(NO, status, YES);
                    return;
                }
            }
            NSDate *expiry = wq_auth_response_expiry(json, cleanLicense, status);
            if (expiry && expiry.timeIntervalSinceNow <= 0) {
                wq_auth_persist_result(cleanLicense, NO, @"expired", expiry);
                completion(NO, @"La licencia expiró.", YES);
                return;
            }
            wq_auth_persist_result(cleanLicense, YES, status.length ? status : @"valid", expiry);
            completion(YES, @"", NO);
        }] resume];
    }] resume];
}

@interface WQAuthGateViewController ()
- (void)completeAuthenticationForLicense:(NSString *)license;
- (void)revalidateSession;
- (void)expireSessionWithMessage:(NSString *)message;
@end

@implementation WQAuthGateViewController {
    UITextField *_licenseField;
    UISwitch *_rememberSwitch;
    UIButton *_continueButton;
    UIActivityIndicatorView *_spinner;
    UILabel *_statusLabel;
    BOOL _validating;
    BOOL _sessionCheckInFlight;
    NSString *_activeLicense;
    NSTimer *_sessionTimer;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"BAIJ STORE MOD";
    wq_prism_install_background(self);
    self.view.backgroundColor = UIColor.clearColor;
    self.view.tintColor = wq_theme_accent();
    [self buildInterface];
    BOOL configured = wq_auth_is_configured();
    _licenseField.enabled = configured;
    _continueButton.enabled = configured;
    if (!configured) {
        _statusLabel.text = @"KeyAuth no está configurado para esta compilación.";
        _statusLabel.textColor = UIColor.systemRedColor;
        return;
    }
    BOOL remember = [NSUserDefaults.standardUserDefaults boolForKey:kWQAuthRememberKey];
    _rememberSwitch.on = remember;
    NSString *saved = remember ? wq_auth_saved_license() : @"";
    _licenseField.text = saved;
    if (saved.length && remember) {
        if (wq_auth_session_is_valid(saved)) [self completeAuthenticationForLicense:saved];
        else [self validateLicense:saved automatic:YES];
    }
}

- (void)buildInterface
{
    UIScrollView *scroll = [UIScrollView new];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.alwaysBounceVertical = YES;
    [self.view addSubview:scroll];
    UIStackView *stack = [[UIStackView alloc] initWithFrame:CGRectZero];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.alignment = UIStackViewAlignmentFill;
    stack.spacing = 22;

    UIView *brandTile = [UIView new];
    brandTile.translatesAutoresizingMaskIntoConstraints = NO;
    brandTile.backgroundColor = wq_theme_accent();
    brandTile.layer.cornerRadius = 17;
    brandTile.layer.cornerCurve = kCACornerCurveContinuous;
    brandTile.clipsToBounds = YES;
    UIImageView *icon = [[UIImageView alloc] initWithImage:[UIImage systemImageNamed:@"key.horizontal.fill"]];
    icon.translatesAutoresizingMaskIntoConstraints = NO;
    icon.contentMode = UIViewContentModeScaleAspectFit;
    icon.tintColor = UIColor.whiteColor;
    [brandTile addSubview:icon];
    [NSLayoutConstraint activateConstraints:@[
        [brandTile.widthAnchor constraintEqualToConstant:58], [brandTile.heightAnchor constraintEqualToConstant:58],
        [icon.centerXAnchor constraintEqualToAnchor:brandTile.centerXAnchor], [icon.centerYAnchor constraintEqualToAnchor:brandTile.centerYAnchor],
        [icon.widthAnchor constraintEqualToConstant:28], [icon.heightAnchor constraintEqualToConstant:28],
    ]];
    UIView *brandRow = [UIView new];
    brandRow.translatesAutoresizingMaskIntoConstraints = NO;
    [brandRow addSubview:brandTile];
    [NSLayoutConstraint activateConstraints:@[
        [brandRow.heightAnchor constraintEqualToConstant:58],
        [brandTile.centerXAnchor constraintEqualToAnchor:brandRow.centerXAnchor],
        [brandTile.centerYAnchor constraintEqualToAnchor:brandRow.centerYAnchor],
    ]];
    UILabel *title = [UILabel new];
    title.text = @"BAIJ STORE MOD";
    title.font = [UIFont systemFontOfSize:28 weight:UIFontWeightBold];
    title.adjustsFontForContentSizeCategory = YES;
    title.textAlignment = NSTextAlignmentCenter;
    title.numberOfLines = 0;
    UILabel *message = [UILabel new];
    message.text = @"Inicia sesión con tu licencia de KeyAuth para continuar.";
    message.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    message.textColor = UIColor.secondaryLabelColor;
    message.numberOfLines = 0;
    message.textAlignment = NSTextAlignmentCenter;
    _licenseField = [UITextField new];
    _licenseField.borderStyle = UITextBorderStyleRoundedRect;
    _licenseField.placeholder = @"Licencia";
    _licenseField.backgroundColor = UIColor.tertiarySystemBackgroundColor;
    _licenseField.layer.cornerRadius = 12;
    _licenseField.layer.cornerCurve = kCACornerCurveContinuous;
    _licenseField.clipsToBounds = YES;
    _licenseField.autocorrectionType = UITextAutocorrectionTypeNo;
    _licenseField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    _licenseField.returnKeyType = UIReturnKeyGo;
    [_licenseField addTarget:self action:@selector(submit) forControlEvents:UIControlEventEditingDidEndOnExit];
    [_licenseField.heightAnchor constraintEqualToConstant:50].active = YES;

    UIButtonConfiguration *button = [UIButtonConfiguration filledButtonConfiguration];
    button.title = @"Continuar";
    button.image = [UIImage systemImageNamed:@"arrow.right"];
    button.imagePlacement = NSDirectionalRectEdgeTrailing;
    button.imagePadding = 8;
    button.cornerStyle = UIButtonConfigurationCornerStyleMedium;
    button.baseBackgroundColor = wq_theme_accent();
    _continueButton = [UIButton buttonWithConfiguration:button primaryAction:[UIAction actionWithHandler:^(__unused UIAction *action) {
        [self submit];
    }]];
    [_continueButton.heightAnchor constraintEqualToConstant:50].active = YES;
    _continueButton.accessibilityHint = @"Valida la licencia con KeyAuth";

    _rememberSwitch = [UISwitch new];
    UILabel *rememberLabel = [UILabel new];
    rememberLabel.text = @"Recordar licencia en este dispositivo";
    rememberLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
    rememberLabel.numberOfLines = 0;
    UIStackView *rememberRow = [[UIStackView alloc] initWithArrangedSubviews:@[rememberLabel, _rememberSwitch]];
    rememberRow.axis = UILayoutConstraintAxisHorizontal;
    rememberRow.alignment = UIStackViewAlignmentCenter;
    rememberRow.spacing = 12;

    UIStackView *progressRow = [[UIStackView alloc] initWithFrame:CGRectZero];
    progressRow.axis = UILayoutConstraintAxisVertical;
    progressRow.alignment = UIStackViewAlignmentCenter;
    progressRow.spacing = 8;
    _spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    _spinner.hidesWhenStopped = YES;
    _statusLabel = [UILabel new];
    _statusLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
    _statusLabel.textColor = UIColor.secondaryLabelColor;
    _statusLabel.numberOfLines = 0;
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    [progressRow addArrangedSubview:_spinner];
    [progressRow addArrangedSubview:_statusLabel];

    UIStackView *form = [[UIStackView alloc] initWithArrangedSubviews:@[_licenseField, _continueButton, rememberRow, progressRow]];
    form.axis = UILayoutConstraintAxisVertical;
    form.alignment = UIStackViewAlignmentFill;
    form.spacing = 16;

    UIView *surface = [UIView new];
    surface.translatesAutoresizingMaskIntoConstraints = NO;
    surface.layer.cornerRadius = 24;
    surface.layer.cornerCurve = kCACornerCurveContinuous;
    surface.clipsToBounds = YES;
    surface.layer.borderWidth = 1;
    surface.layer.borderColor = UIColor.separatorColor.CGColor;
    surface.backgroundColor = wq_theme_card() ?: [UIColor colorWithWhite:0.5 alpha:0.05];
    UIVisualEffectView *blur = [[UIVisualEffectView alloc] initWithEffect:[UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemMaterial]];
    blur.translatesAutoresizingMaskIntoConstraints = NO;
    blur.userInteractionEnabled = NO;
    [surface addSubview:blur];
    [NSLayoutConstraint activateConstraints:@[
        [blur.topAnchor constraintEqualToAnchor:surface.topAnchor], [blur.bottomAnchor constraintEqualToAnchor:surface.bottomAnchor],
        [blur.leadingAnchor constraintEqualToAnchor:surface.leadingAnchor], [blur.trailingAnchor constraintEqualToAnchor:surface.trailingAnchor],
    ]];
    [surface addSubview:form];
    form.translatesAutoresizingMaskIntoConstraints = NO;
    [NSLayoutConstraint activateConstraints:@[
        [form.topAnchor constraintEqualToAnchor:surface.topAnchor constant:22],
        [form.bottomAnchor constraintEqualToAnchor:surface.bottomAnchor constant:-22],
        [form.leadingAnchor constraintEqualToAnchor:surface.leadingAnchor constant:20],
        [form.trailingAnchor constraintEqualToAnchor:surface.trailingAnchor constant:-20],
    ]];

    [stack addArrangedSubview:brandRow];
    [stack addArrangedSubview:title];
    [stack addArrangedSubview:message];
    [stack addArrangedSubview:surface];
    [scroll addSubview:stack];
    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [scroll.topAnchor constraintEqualToAnchor:safe.topAnchor], [scroll.bottomAnchor constraintEqualToAnchor:self.view.keyboardLayoutGuide.topAnchor],
        [scroll.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor], [scroll.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [stack.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor constant:32],
        [stack.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor constant:-32],
        [stack.leadingAnchor constraintGreaterThanOrEqualToAnchor:scroll.frameLayoutGuide.leadingAnchor constant:22],
        [stack.trailingAnchor constraintLessThanOrEqualToAnchor:scroll.frameLayoutGuide.trailingAnchor constant:-22],
        [stack.centerXAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.centerXAnchor],
        [stack.widthAnchor constraintGreaterThanOrEqualToConstant:260],
        [stack.widthAnchor constraintLessThanOrEqualToConstant:520],
    ]];
}

- (void)submit
{
    [self validateLicense:_licenseField.text ?: @"" automatic:NO];
}

- (void)validateLicense:(NSString *)license automatic:(BOOL)automatic
{
    if (_validating) return;
    _validating = YES;
    _continueButton.enabled = NO;
    _licenseField.enabled = NO;
    _rememberSwitch.enabled = NO;
    _statusLabel.text = @"Validando licencia con KeyAuth…";
    _statusLabel.textColor = UIColor.secondaryLabelColor;
    [_spinner startAnimating];
    __weak typeof(self) weakSelf = self;
    wq_auth_validate(license, ^(BOOL valid, NSString *message, BOOL definitiveFailure) {
        dispatch_async(dispatch_get_main_queue(), ^{
            WQAuthGateViewController *screen = weakSelf;
            if (!screen) return;
            screen->_validating = NO;
            [screen->_spinner stopAnimating];
            screen->_continueButton.enabled = YES;
            screen->_licenseField.enabled = YES;
            screen->_rememberSwitch.enabled = YES;
            if (!valid) {
                NSString *saved = wq_auth_saved_license();
                NSString *cleanLicense = [license stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
                if (definitiveFailure && (automatic || [saved isEqualToString:cleanLicense])) {
                    wq_auth_delete_license();
                    [NSUserDefaults.standardUserDefaults setBool:NO forKey:kWQAuthRememberKey];
                    screen->_rememberSwitch.on = NO;
                }
                screen->_statusLabel.text = message;
                screen->_statusLabel.textColor = UIColor.systemRedColor;
                return;
            }
            BOOL remember = screen->_rememberSwitch.isOn;
            [NSUserDefaults.standardUserDefaults setBool:remember forKey:kWQAuthRememberKey];
            [screen completeAuthenticationForLicense:[license stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]];
        });
    });
}

- (void)completeAuthenticationForLicense:(NSString *)license
{
    _activeLicense = [license copy];
    [self beginSessionMonitoring];
    void (^authenticated)(NSURL *) = self.onAuthenticated;
    NSURL *pendingURL = self.pendingURL;
    self.pendingURL = nil;
    if (authenticated) authenticated(pendingURL);
}

- (void)beginSessionMonitoring
{
    if (!_activeLicense.length || _sessionTimer.valid) return;
    _sessionTimer = [NSTimer scheduledTimerWithTimeInterval:10.0 target:self
        selector:@selector(revalidateSession) userInfo:nil repeats:YES];
}

- (void)revalidateSession
{
    if (_sessionCheckInFlight || !_activeLicense.length) return;
    if (wq_auth_should_force_logout()) {
        [self expireSessionWithMessage:@"La licencia venció o fue revocada. Inicia sesión de nuevo."];
        return;
    }
    NSString *license = [_activeLicense copy];
    BOOL recentConfirmation = wq_auth_session_is_valid(license);
    _sessionCheckInFlight = YES;
    __weak typeof(self) weakSelf = self;
    wq_auth_validate(license, ^(BOOL valid, NSString *message, BOOL definitiveFailure) {
        dispatch_async(dispatch_get_main_queue(), ^{
            WQAuthGateViewController *screen = weakSelf;
            if (!screen) return;
            screen->_sessionCheckInFlight = NO;
            if (valid) return;
            if (definitiveFailure || !recentConfirmation) {
                [screen expireSessionWithMessage:message.length ? message : @"La sesión de KeyAuth ya no es válida. Inicia sesión de nuevo."];
            }
        });
    });
}

- (void)expireSessionWithMessage:(NSString *)message
{
    [_sessionTimer invalidate];
    _sessionTimer = nil;
    _activeLicense = nil;
    wq_auth_clear_session();
    _rememberSwitch.on = NO;
    _licenseField.text = @"";
    _statusLabel.text = message;
    _statusLabel.textColor = UIColor.systemRedColor;
    void (^expired)(void) = self.onAuthenticationExpired;
    if (expired) expired();
}

- (void)showSessionExpired
{
    [self expireSessionWithMessage:@"La sesión de KeyAuth venció. Inicia sesión de nuevo."];
}

@end