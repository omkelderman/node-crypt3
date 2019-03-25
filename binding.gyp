{
    "targets": [
        {
            "target_name": "cryptbindings",
            "sources": [
                "cryptbindings.cc",
                "cryptbindings-async.cc",
                "cryptbindings-sync.cc"
            ],
            "link_settings": {
                "libraries": [
                    "-lcrypt"
                ]
            }
        }
    ]
}