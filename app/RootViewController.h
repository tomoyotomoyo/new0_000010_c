//
//  RootViewController.h
//  WKWebView terminal + JS Bridge + KFKernel integration
//

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>

@interface RootViewController : UIViewController <WKScriptMessageHandler, WKNavigationDelegate>
@end
