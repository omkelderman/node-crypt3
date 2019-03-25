#include "cryptbindings-async.h"

#include <node.h>
#include <uv.h>
#include <cerrno>
#include <cstring>
#include <crypt.h>

#include <string>

namespace cryptbindings
{

using v8::Exception;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::NewStringType;
using v8::Null;
using v8::Persistent;
using v8::String;
using v8::Undefined;
using v8::Value;
using v8::Context;

struct Work
{
    // uv stuff
    uv_work_t request;

    // input
    std::string key;
    std::string salt;
    Persistent<Function> callback;

    // output
    int errorNumber;
    std::string result;
};

void WorkAsync(uv_work_t *req)
{
    Work *work = static_cast<Work *>(req->data);

    const char *result = crypt(work->key.c_str(), work->salt.c_str());
    if (result == nullptr)
    {
        work->errorNumber = errno;
    }
    else
    {
        work->errorNumber = 0;
        work->result.assign(result);
    }
}

void WorkAsyncComplete(uv_work_t *req, int status)
{
    Isolate *isolate = Isolate::GetCurrent();
    v8::HandleScope handleScope(isolate);
    Local<Context> context = isolate->GetCurrentContext();

    Work *work = static_cast<Work *>(req->data);
    Local<Function> cb = work->callback.Get(isolate);

    if (work->errorNumber == 0)
    {
        // success
        auto result = String::NewFromUtf8(isolate, work->result.c_str(), NewStringType::kNormal).ToLocalChecked();

        const int argc = 2;
        Local<Value> argv[argc] = {Null(isolate), result};
        cb->Call(context, Null(isolate), argc, argv);
    }
    else
    {
        // error
        auto errnoMessage = strerror(work->errorNumber);
        auto err = node::ErrnoException(isolate, work->errorNumber, "crypt", errnoMessage);

        const int argc = 1;
        Local<Value> argv[argc] = {err};
        cb->Call(context, Null(isolate), argc, argv);
    }

    work->callback.Reset();
    delete work;
}

void ExecuteCryptAsync(const FunctionCallbackInfo<Value> &args)
{
    Isolate *isolate = args.GetIsolate();

    if (args.Length() < 3)
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments", NewStringType::kNormal).ToLocalChecked()));
        return;
    }

    if (!args[0]->IsString() || !args[1]->IsString() || !args[2]->IsFunction())
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Arguments of wrong type", NewStringType::kNormal).ToLocalChecked()));
        return;
    }

    String::Utf8Value key(isolate, args[0]->ToString());
    String::Utf8Value salt(isolate, args[1]->ToString());
    auto callback = Local<Function>::Cast(args[2]);

    // create work
    Work *work = new Work();
    work->request.data = work;
    work->key.assign(*key);
    work->salt.assign(*salt);
    work->callback.Reset(isolate, callback);

    // queue work
    uv_queue_work(uv_default_loop(), &work->request, WorkAsync, WorkAsyncComplete);

    args.GetReturnValue().Set(Undefined(isolate));
}

} // namespace cryptbindings