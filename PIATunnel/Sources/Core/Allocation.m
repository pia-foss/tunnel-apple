//
//  Allocation.m
//  PIATunnel
//
//  Created by Davide De Rosa on 5/5/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

#import <stdlib.h>

#import "Allocation.h"

#define MAX_BLOCK_SIZE  16  // AES only, block is 128-bit

void *allocate_safely(size_t size) {
    void *memory = malloc(size);
    if (!memory) {
//        abort("malloc() call failed")
        abort();
        return NULL;
    }
    return memory;
}

size_t safe_crypto_capacity(size_t size, size_t overhead) {

    // encryption, byte-alignment, overhead (e.g. IV, digest)
    return 2 * size + MAX_BLOCK_SIZE + overhead;
}
