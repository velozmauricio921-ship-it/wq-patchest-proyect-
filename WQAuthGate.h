#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface WQAuthGateViewController : UIViewController
@property (nonatomic, copy, nullable) void (^onAuthenticated)(NSURL *_Nullable pendingURL);
@property (nonatomic, copy, nullable) void (^onAuthenticationExpired)(void);
@property (nonatomic, copy, nullable) NSURL *pendingURL;
- (void)beginSessionMonitoring;
- (void)showSessionExpired;
@end

NS_ASSUME_NONNULL_END