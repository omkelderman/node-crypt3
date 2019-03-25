#include "cryptbindings-sync.h"

#include <node.h>
#include <cerrno>
#include <cstring>
#include <crypt.h>

namespace cryptbindings
{

using v8::Exception;
using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::NewStringType;
using v8::String;
using v8::Value;

void ExecuteCryptSync(const FunctionCallbackInfo<Value> &args)
{
    Isolate *isolate = args.GetIsolate();

    if (args.Length() < 2)
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments", NewStringType::kNormal).ToLocalChecked()));
        return;
    }

    if (!args[0]->IsString() || !args[1]->IsString())
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Arguments not of type string", NewStringType::kNormal).ToLocalChecked()));
        return;
    }

    String::Utf8Value key(isolate, args[0]->ToString());
    String::Utf8Value salt(isolate, args[1]->ToString());

    const char *result = crypt(*key, *salt);
    if (result == nullptr)
    {
        auto errnoMessage = strerror(errno);
        auto err = node::ErrnoException(isolate, errno, "crypt", errnoMessage);
        isolate->ThrowException(err);
        return;
    }

    args.GetReturnValue().Set(String::NewFromUtf8(isolate, result, NewStringType::kNormal).ToLocalChecked());
}

} // namespace cryptbindings