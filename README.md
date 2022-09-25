# integrity_experiments
A (simple) integrity checking system in the form of MSVC macros, PRs are welcome.

## What is this?
A header only "library" I wrote some time ago when experimenting with integrity checking using macros. Works best if used along a virtualizing packer as a second layer of integrity checks.

## Some tips
Works best on non-inlined functions, preferably side by side with a code virtualizing packer. 

For the best results, you're going to want to put several integrity checking macros all over your program in your core algorithms, preferably wrapped in virtualization macros, depending on your packer of choice.

Something like this can help when you're using pre-built libraries or simple OS libraries and you cannot rely on them not having been tampered with.