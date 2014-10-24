{
  "targets": [
    {
      "target_name": "net",
      "sources": [
        "src/net.c",
        "src/tls.c",
      ],
      "cflags": [
        "-Wno-trigraphs"
      ],
      "defines": [
        "HAVE_SNPRINTF"
      ],
      "include_dirs" : [
        "include",
        "deps",
        "<!(node -e \"require('nan')\")",
      ],
    },
  ]
}
