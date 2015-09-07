//
//  ViewController.m
//  TrustedID_iOS
//
//  Created by lichang on 15/8/24.
//  Copyright (c) 2015年 lichang. All rights reserved.
//

#import "ViewController.h"
//获取Open UDID
#import <CommonCrypto/CommonDigest.h>
//获取MAC地址
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
//获取 IP 地址
#import <ifaddrs.h>
#import <arpa/inet.h>
//WiFi MAC
#import <SystemConfiguration/CaptiveNetwork.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)getInfo:(id)sender {
    ViewController *viewController = [[ViewController alloc]init];
    NSLog(@"设备操作系统：%@",viewController.getOperationSystem);
    [viewController getTime];
    NSLog(@"Open UDID：%@",viewController.getOpenUDID);
    NSLog(@"APP 版本号%@",viewController.getAppVersion);
    NSLog(@"Mac 地址：%@",viewController.getMacAddress);
    NSLog(@"IP 地址：%@",viewController.getIPAddress);
    NSLog(@"IMEI：%@",viewController.getIMEI);
    NSLog(@"设备型号：%@",viewController.getDeviceType);
    NSLog(@"设备生产商：%@",viewController.getDeviceProducer);
    NSLog(@"设备操作系统版本：%@",viewController.getDeviceOSVersion);
    NSLog(@"系统语言：%@",viewController.getSystemLanguage);
    NSLog(@"设备所在时区：%@",viewController.getSystemTimeZone);
    NSLog(@"设备所在区域：%@",viewController.getSystemArea);
    NSLog(@"设备网络状态：%@",viewController.getNetworkType);
    NSLog(@"设备 WI-FI Mac 地址：%@",viewController.getWifiMacAddress);
    NSLog(@"Device Token：%@",viewController.getDeviceToken);
    NSLog(@"设备是否越狱：%@",viewController.deviceIsRoot);
    NSLog(@"IDFA：%@",viewController.getIDFA);
    NSLog(@"设备地理位置：%@",viewController.getLocation);
    
}

-(NSString *)getOperationSystem{
    NSString *operationSystem =[[UIDevice currentDevice] systemName];
    return operationSystem;
}

-(void)getTime{
    NSURL *url=[NSURL URLWithString:@"http://www.baidu.com"];
    NSURLRequest *request=[NSURLRequest requestWithURL:url];
    NSURLConnection *connection=[[NSURLConnection alloc]initWithRequest:request delegate:self startImmediately:YES];
    [connection start];
    
    //异步请求获取中时区时间戳
    //    NSURL *url=[NSURL URLWithString:@"http://www.baidu.com"];
    //    NSString *post=@"postData";
    //    NSData *postData = [post dataUsingEncoding:NSASCIIStringEncoding allowLossyConversion:YES];
    //    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    //    [request setHTTPMethod:@"POST"];
    //    [request setHTTPBody:postData];
    //    [request setTimeoutInterval:10.0];
    //    NSOperationQueue *queue = [[NSOperationQueue alloc]init];
    //    [NSURLConnection sendAsynchronousRequest:request
    //                                       queue:queue
    //                           completionHandler:^(NSURLResponse *response, NSData *data, NSError *error){
    //                               if (error) {
    //                                   NSLog(@"Httperror:%@%d", error.localizedDescription,error.code);
    //                               }else{
    //                                   NSHTTPURLResponse *httpResponse=(NSHTTPURLResponse *)response;
    //                                   if ([response respondsToSelector:@selector(allHeaderFields)]) {
    //                                       NSDictionary *dic=[httpResponse allHeaderFields];
    //                                       NSString *time=[dic objectForKey:@"Date"];
    //                                       NSLog(@"与系统无关的时间戳 = %@",time);
    //                                   }
    //                               }
    //                           }];
}

- (NSString *)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    NSString *time = nil;
    NSHTTPURLResponse *httpResponse=(NSHTTPURLResponse *)response;
    if ([response respondsToSelector:@selector(allHeaderFields)]) {
        NSDictionary *dic=[httpResponse allHeaderFields];
        NSString *time=[dic objectForKey:@"Date"];
        NSLog(@"与系统无关的时间戳：%@",time);
    }
    return time;
}

-(NSString *)getAppVersion{
    NSDictionary *infoDictionary = [[NSBundle mainBundle] infoDictionary];
    NSString *appVersion =[infoDictionary objectForKey:@"CFBundleShortVersionString"];
    return appVersion;
}

-(NSString *)getOpenUDID{
    unsigned char result[16];
    const char *cStr = [[[NSProcessInfo processInfo] globallyUniqueString] UTF8String];
    CC_MD5( cStr, strlen(cStr), result );
    NSString *openUDID = [NSString stringWithFormat:
                          @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%08llx",
                          result[0], result[1], result[2], result[3],
                          result[4], result[5], result[6], result[7],
                          result[8], result[9], result[10], result[11],
                          result[12], result[13], result[14], result[15],
                          arc4random() % 4294967295];
    return openUDID;
}

-(NSString *)getMacAddress{
    int                 mgmtInfoBase[6];
    char                *msgBuffer = NULL;
    size_t              length;
    unsigned char       macAddress[6];
    struct if_msghdr    *interfaceMsgStruct;
    struct sockaddr_dl  *socketStruct;
    NSString            *errorFlag = NULL;
    mgmtInfoBase[0] = CTL_NET;        // Request network subsystem
    mgmtInfoBase[1] = AF_ROUTE;       // Routing table info
    mgmtInfoBase[2] = 0;
    mgmtInfoBase[3] = AF_LINK;        // Request link layer information
    mgmtInfoBase[4] = NET_RT_IFLIST;  // Request all configured interfaces
    if ((mgmtInfoBase[5] = if_nametoindex("en0")) == 0)
        errorFlag = @"if_nametoindex failure";
    else
    {
        if (sysctl(mgmtInfoBase, 6, NULL, &length, NULL, 0) < 0)
            errorFlag = @"sysctl mgmtInfoBase failure";
        else
        {
            if ((msgBuffer = malloc(length)) == NULL)
                errorFlag = @"buffer allocation failure";
            else
            {
                if (sysctl(mgmtInfoBase, 6, msgBuffer, &length, NULL, 0) < 0)
                    errorFlag = @"sysctl msgBuffer failure";
            }
        }
    }
    if (errorFlag != NULL)
    {
        NSLog(@"Error: %@", errorFlag);
    }
    interfaceMsgStruct = (struct if_msghdr *) msgBuffer;
    socketStruct = (struct sockaddr_dl *) (interfaceMsgStruct + 1);
    memcpy(&macAddress, socketStruct->sdl_data + socketStruct->sdl_nlen, 6);
    NSString *macAddressString = [NSString stringWithFormat:@"%02x:%02x:%02x:%02x:%02x:%02x",
                                  macAddress[0], macAddress[1], macAddress[2],
                                  macAddress[3], macAddress[4], macAddress[5]];
    return macAddressString;
}

-(NSString *)getIPAddress{
    NSString *address = @"error";
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    // retrieve the current interfaces - returns 0 on success
    success = getifaddrs(&interfaces);
    if (success == 0) {
        // Loop through linked list of interfaces
        temp_addr = interfaces;
        while(temp_addr != NULL) {
            if(temp_addr->ifa_addr->sa_family == AF_INET) {
                // Check if interface is en0 which is the wifi connection on the iPhone
                if([[NSString stringWithUTF8String:temp_addr->ifa_name] isEqualToString:@"en0"]) {
                    // Get NSString from C String
                    address = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr)];
                }
            }
            temp_addr = temp_addr->ifa_next;
        }
    }
    freeifaddrs(interfaces);
    return address;
}

-(NSString *)getIMEI{
    //无法获取
    return @"已被禁用，获取不到";
}

-(NSString *)getDeviceType{
    NSString *deviceType = [[UIDevice currentDevice] model];
    NSLog(@"localizedModel: %@", [[UIDevice currentDevice] localizedModel]);
    return deviceType;
}

-(NSString *)getDeviceProducer{
    return @"Apple";
}

-(NSString *)getDeviceOSVersion{
    NSString *systemVersion =[[UIDevice currentDevice] systemVersion];
    return systemVersion;
}

-(NSString *)getSystemLanguage{
    NSUserDefaults* defs = [NSUserDefaults standardUserDefaults];
    NSArray* languages = [defs objectForKey:@"AppleLanguages"];
    NSString* preferredLang = [languages objectAtIndex:0];
    return preferredLang;
}

-(NSString *)getSystemArea{
    NSString *countryCode = [[NSLocale currentLocale] objectForKey:NSLocaleCountryCode];
    return countryCode;
}

-(NSString *)getSystemTimeZone{
    NSTimeZone *timeZone = [NSTimeZone systemTimeZone];
    NSString *systemTimeZone = (NSString *)timeZone;
    return systemTimeZone;
}

-(NSString *)getNetworkType{
    UIApplication *app = [UIApplication sharedApplication];
    NSArray *children = [[[app valueForKeyPath:@"statusBar"] valueForKeyPath:@"foregroundView"] subviews];
    int type = 0;
    for (id child in children) {
        if ([child isKindOfClass:[NSClassFromString(@"UIStatusBarDataNetworkItemView") class]]) {
            type = [[child valueForKeyPath:@"dataNetworkType"] intValue];
        }
    }
    NSString *stateString = @"";
    switch (type) {
        case 0:
            stateString = @"notReachable";
            break;
        case 1:
            stateString = @"2G";
            break;
        case 2:
            stateString = @"3G";
            break;
        case 3:
            stateString = @"4G";
            break;
        case 4:
            stateString = @"LTE";
            break;
        case 5:
            stateString = @"wifi";
            break;
        default:
            break;
    }
    return stateString;
}

-(NSString *)getWifiMacAddress{
    NSString *ssid = @"Not Found";
    NSString *macIp = @"Not Found";
    CFArrayRef myArray = CNCopySupportedInterfaces();
    if (myArray != nil) {
        CFDictionaryRef myDict = CNCopyCurrentNetworkInfo(CFArrayGetValueAtIndex(myArray, 0));
        if (myDict != nil) {
            NSDictionary *dict = (NSDictionary*)CFBridgingRelease(myDict);
            ssid = [dict valueForKey:@"SSID"];
            macIp = [dict valueForKey:@"BSSID"];
        }
    }
    return macIp;
}

-(NSString *)getDeviceToken{
    //需要获取推送的权限才能获取
    //DeviceToken: {<cbad285b 632ce36b fba3c3ee 61cef046 18ef676e c345bb1b f87c15a4 af08f03b>}
    return @"需要权限";
}

-(NSString *)deviceIsRoot{
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/User/Applications/"]) {
        NSLog(@"该设备已越狱");
        NSArray *applist = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/User/Applications/" error:nil];
        NSLog(@"applist = %@", applist);
        return @"已越狱";
    }
    else{
        return @"未越狱";
    }
}


-(NSString *)getIDFA{
    NSString *IDFA =[[[UIDevice currentDevice] identifierForVendor] UUIDString];
    return IDFA;
}

-(NSString *)getLocation{
    //需要用户同意权限
    return @"需要同意权限";
}

@end
