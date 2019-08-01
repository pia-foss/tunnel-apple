source 'https://github.com/CocoaPods/Specs.git'
platform :ios, '11.0'
use_frameworks!

# ignore all warnings from all pods
inhibit_all_warnings!

abstract_target 'PIATunnel' do
    pod 'SwiftyBeaver', '~> 1.7.0'
   #pod 'OpenSSL-Apple', "~> 1.1.0h"
        pod 'OpenSSL-Apple', '~> 1.1.0j.2'
	

    target 'PIATunnel-iOS' do
        platform :ios, '11.0'
    end
    target 'PIATunnelHost' do
        platform :ios, '11.0'
    end

    target 'PIATunnel-macOS' do
        platform :osx, '10.11'
    end
end
