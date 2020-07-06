//
//  ViewController.m
//  libzmq-ios
//
//  Created by rsm on 05/07/2020.
//  Copyright © 2020 mileschet. All rights reserved.
//

#import "ViewController.h"
#import "include/zmq.h"
#import "include/zmq_utils.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    NSLog(@"%d", ZMQ_EVENT_CONNECTED);
}


@end
