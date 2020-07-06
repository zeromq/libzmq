//
//  AppDelegate.h
//  libzmq-ios
//
//  Created by rsm on 05/07/2020.
//  Copyright © 2020 mileschet. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <CoreData/CoreData.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (readonly, strong) NSPersistentContainer *persistentContainer;

- (void)saveContext;


@end

