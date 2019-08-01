Pod::Spec.new do |s|
    s.name              = "PIATunnel"
    s.version           = "2.0.2"
    s.summary           = "PIA tunnel implementation in Swift."

    s.homepage          = "https://www.privateinternetaccess.com/"
    s.license           = { :type => "MIT", :file => "LICENSE" }
    s.author            = { "Jose Blaya" => "joseblaya@londontrustmedia.com", "Davide De Rosa" => "" }
    s.source            = { :git => "https://github.com/pia-foss/tunnel-apple.git", :tag => "v#{s.version}" }

    s.ios.deployment_target = "11.0"
    s.osx.deployment_target = "10.11"

    s.subspec "Core" do |p|
        p.source_files          = "PIATunnel/Sources/Core/**/*.{h,m,swift}"
        p.private_header_files  = "PIATunnel/Sources/Core/**/*.h"
        p.preserve_paths        = "PIATunnel/Sources/Core/*.modulemap"
        p.pod_target_xcconfig   = { "SWIFT_INCLUDE_PATHS" => "${PODS_TARGET_SRCROOT}/PIATunnel/Sources/Core",
                                    "APPLICATION_EXTENSION_API_ONLY" => "YES" }
        p.dependency "SwiftyBeaver"
        p.dependency "OpenSSL-Apple", "~> 1.1.0j.2"
    end

    s.subspec "AppExtension" do |p|
        p.source_files          = "PIATunnel/Sources/AppExtension/**/*.swift"
        p.resources             = "PIATunnel/Resources/AppExtension/**/*"
        p.frameworks            = "NetworkExtension"
        p.pod_target_xcconfig   = { "APPLICATION_EXTENSION_API_ONLY" => "YES" }

        p.dependency "PIATunnel/Core"
        p.dependency "SwiftyBeaver"
    end
end
