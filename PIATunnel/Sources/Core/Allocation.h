//
//  Allocation.h
//  PIATunnel
//
//  Created by Davide De Rosa on 5/5/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <stddef.h>

void *allocate_safely(size_t size);

size_t safe_crypto_capacity(size_t size, size_t overhead);
