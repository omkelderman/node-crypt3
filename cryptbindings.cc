#include <node.h>
#include "cryptbindings-sync.h"
#include "cryptbindings-async.h"

namespace cryptbindings
{

void Initialize(v8::Local<v8::Object> exports)
{
    NODE_SET_METHOD(exports, "cryptSync", ExecuteCryptSync);
    NODE_SET_METHOD(exports, "cryptAsync", ExecuteCryptAsync);
}

NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)

} // namespace cryptbindings
