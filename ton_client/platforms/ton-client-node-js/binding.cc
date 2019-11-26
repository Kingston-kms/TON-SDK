#define NAPI_EXPERIMENTAL
#include <assert.h>
#include <memory.h>
#include <node_api.h>
#include <stdio.h>
#include <uv.h>

enum InteropResultFlags {
    RESULT_FINISHED = 1,
};

typedef uint32_t InteropContext;
typedef struct
{
    const uint8_t* content;
    uint32_t len;
} InteropString;

typedef struct
{
    InteropString result_json;
    InteropString error_json;
} InteropJsonResponse;

typedef struct
{
} InteropJsonResponseHandle;

#ifdef __APPLE__

#include <dlfcn.h>
#include <iostream>
#include <string>

using std::cerr;

struct Lib {
    void* handle;
    InteropContext (*tc_create_context)();
    void (*tc_destroy_context)(InteropContext context);
    InteropJsonResponseHandle* (*tc_json_request)(
        InteropContext context,
        InteropString method_name,
        InteropString params_json);
    InteropJsonResponse* (*tc_read_json_response)(const InteropJsonResponseHandle* response);
    void (*tc_destroy_json_response)(const InteropJsonResponseHandle* response);
};

static Lib lib_instance
    = { nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };

void bind(void** ptr, const char* name)
{
    *ptr = (void*)dlsym(lib_instance.handle, name);
    if (*ptr == nullptr) {
        cerr << "[" << __FILE__
             << "] Unable to find [ton_sdk_json_rpc_request] function: "
             << dlerror() << "\n";
        exit(EXIT_FAILURE);
    }
}

Lib& lib()
{
    if (lib_instance.handle == nullptr) {
        Dl_info info;
        if (!dladdr((void*)lib, &info)) {
            cerr << "[" << __FILE__ << "]: Unable to get lib info: " << dlerror()
                 << "\n";
            exit(EXIT_FAILURE);
        }
        auto libpath = std::string(info.dli_fname);
        auto slash_pos = libpath.find_last_of("/\\");
        if (slash_pos != std::string::npos) {
            libpath = libpath.substr(0, slash_pos) + "/libtonclientnodejs.dylib";
        }

        lib_instance.handle = dlopen(libpath.c_str(), RTLD_LOCAL);
        if (lib_instance.handle == nullptr) {
            cerr << "[" << __FILE__ << "]: Unable to open library: " << dlerror()
                 << "\n";
            exit(EXIT_FAILURE);
        }
        bind((void**)&lib_instance.tc_create_context, "tc_create_context");
        bind((void**)&lib_instance.tc_destroy_context, "tc_destroy_context");
        bind((void**)&lib_instance.tc_json_request, "tc_json_request");
        bind((void**)&lib_instance.tc_read_json_response, "tc_read_json_response");
        bind((void**)&lib_instance.tc_destroy_json_response, "tc_destroy_json_response");
    }
    return lib_instance;
}

InteropContext tc_create_context()
{
    return lib().tc_create_context();
}

void tc_destroy_context(InteropContext context)
{
    lib().tc_destroy_context(context);
}

const InteropJsonResponseHandle* tc_json_request(
    InteropContext context,
    InteropString method_name,
    InteropString params_json)
{
    return lib().tc_json_request(context, method_name, params_json);
}

const InteropJsonResponse* tc_read_json_response(const InteropJsonResponseHandle* response)
{
    return lib().tc_read_json_response(response);
}

void tc_destroy_json_response(const InteropJsonResponseHandle* response)
{
    lib().tc_destroy_json_response(response);
}
#else

#ifdef __cplusplus
extern "C" {
#endif

InteropContext tc_create_context();
void tc_destroy_context(InteropContext context);
const InteropJsonResponseHandle* tc_json_request(
    InteropContext context,
    InteropString method_name,
    InteropString params_json);
const InteropJsonResponse* tc_read_json_response(const InteropJsonResponseHandle* response);
void tc_destroy_json_response(const InteropJsonResponseHandle* response);

#ifdef __cplusplus
}
#endif
#endif

#define CHECK(status) assert((status) == napi_ok)

// Utility

napi_value
napiUndefined(napi_env env)
{
    napi_value undefined;
    CHECK(napi_get_undefined(env, &undefined));
    return undefined;
}

napi_value
napiGlobal(napi_env env)
{
    napi_value global;
    CHECK(napi_get_global(env, &global));
    return global;
}

napi_value
napiString(napi_env env, const InteropString& ts)
{
    napi_value result;
    CHECK(napi_create_string_utf8(env, (const char*)ts.content, ts.len, &result));
    return result;
}

napi_value
napiUInt32(napi_env env, uint32_t v)
{
    napi_value result;
    CHECK(napi_create_uint32(env, v, &result));
    return result;
}

napi_value
napiString(napi_env env, const char* s)
{
    napi_value value;
    CHECK(napi_create_string_utf8(env, s, NAPI_AUTO_LENGTH, &value));
    return value;
}

InteropString
tonString(napi_env env, napi_value ns)
{
    InteropString result;
    size_t bytesRequired;
    CHECK(napi_get_value_string_utf8(env, ns, nullptr, 0, &bytesRequired));
    uint8_t* ptr = new uint8_t[bytesRequired + 1];
    size_t len = 0;
    CHECK(
        napi_get_value_string_utf8(env, ns, (char*)ptr, bytesRequired + 1, &len));
    result.content = ptr;
    result.len = len;
    return result;
}

uint32_t
napiGetUInt32(napi_env env, napi_value nv)
{
    uint32_t result = 0;
    CHECK(napi_get_value_uint32(env, nv, &result));
    return result;
}

InteropString
tonString(const InteropString& source)
{
    InteropString result;
    result.content = new uint8_t[source.len];
    memcpy((void*)result.content, source.content, source.len);
    result.len = source.len;
    return result;
}

void tonStringFree(InteropString& source)
{
    delete source.content;
    source.content = nullptr;
    source.len = 0;
}

// Request

// Adapter

struct NodeJsAdapter {
    struct Request {
        typedef int32_t Id;
        Id id;
        Request* next;
        napi_threadsafe_function onResult;

        Request(Id id, Request* next)
            : id(id)
            , next(next)
            , onResult(nullptr)
        {
        }
    };

    struct Result {
        Request::Id requestId;
        InteropString resultJson;
        InteropString errorJson;
        bool finished;

        Result(Request::Id requestId,
            InteropString& resultJson,
            InteropString& errorJson,
            bool finished)
            : requestId(requestId)
            , resultJson(tonString(resultJson))
            , errorJson(tonString(errorJson))
            , finished(finished)
        {
        }
        ~Result()
        {
            tonStringFree(resultJson);
            tonStringFree(errorJson);
        }
    };

    Request::Id nextRequestId = 0;
    Request* firstRequest = nullptr;
    uv_rwlock_t lock;

    NodeJsAdapter()
        : nextRequestId(1)
        , firstRequest(nullptr)
    {
        uv_rwlock_init(&lock);
    }

    ~NodeJsAdapter() { uv_rwlock_destroy(&lock); }

    void beginRead() { uv_rwlock_rdlock(&lock); }

    void endRead() { uv_rwlock_rdunlock(&lock); }

    void beginWrite() { uv_rwlock_wrlock(&lock); }

    void endWrite() { uv_rwlock_wrunlock(&lock); }

    Request* createRequest()
    {
        firstRequest = new Request(nextRequestId++, firstRequest);
        return firstRequest;
    }

    Request** findRequestPtr(Request::Id id)
    {
        auto ptr = &firstRequest;
        while (*ptr && (*ptr)->id != id) {
            ptr = &(*ptr)->next;
        }
        return ptr;
    }

    void request(napi_env env, int argc, napi_value* args)
    {
        beginWrite();
        auto request = createRequest();
        CHECK(napi_create_threadsafe_function(env,
            args[3],
            nullptr,
            napiString(env, "TON Client JsonApi"),
            0,
            1,
            nullptr,
            nullptr,
            nullptr,
            callHandler,
            &request->onResult));
        CHECK(napi_ref_threadsafe_function(env, request->onResult));
        endWrite();

        auto context = napiGetUInt32(env, args[0]);
        auto method = tonString(env, args[1]);
        auto paramsJson = tonString(env, args[2]);
        auto responseHandle = tc_json_request(context, method, paramsJson);
        auto response = tc_read_json_response(responseHandle);
        resultHandler(request->id, response->result_json, response->error_json, RESULT_FINISHED);
        tc_destroy_json_response(responseHandle);
        tonStringFree(method);
        tonStringFree(paramsJson);
    }

    void onResult(Request::Id id,
        InteropString resultJson,
        InteropString errorJson,
        InteropResultFlags flags)
    {
        beginWrite();
        auto request = *findRequestPtr(id);
        if (request) {
            auto result = new Result(id, resultJson, errorJson, (flags & RESULT_FINISHED) != 0);
            CHECK(napi_acquire_threadsafe_function(request->onResult));
            CHECK(napi_call_threadsafe_function(
                request->onResult, result, napi_tsfn_blocking));
            CHECK(
                napi_release_threadsafe_function(request->onResult, napi_tsfn_release));
        }
        endWrite();
    }

    void onCall(napi_env env, napi_value onResult, void* context, void* data)
    {
        auto result = (Result*)data;
        beginWrite();
        auto ptr = findRequestPtr(result->requestId);
        auto request = *ptr;
        if (request && result->finished) {
            *ptr = request->next;
        }
        endWrite();
        if (request) {
            napi_value args[2];
            napi_value callResult;
            args[0] = napiString(env, result->resultJson);
            args[1] = napiString(env, result->errorJson);
            CHECK(napi_call_function(
                env, napiGlobal(env), onResult, 2, args, &callResult));
            if (result->finished) {
                CHECK(napi_unref_threadsafe_function(env, request->onResult));
                delete request;
            }
        }
        delete result;
    }

    static void resultHandler(int32_t request_id,
        InteropString result_json,
        InteropString error_json,
        int32_t flags)
    {
        auto adapter = shared;
        if (adapter) {
            adapter->onResult(request_id, result_json, error_json, (InteropResultFlags)flags);
        }
    }

    static void callHandler(napi_env env,
        napi_value onResult,
        void* context,
        void* data)
    {
        auto adapter = shared;
        if (adapter) {
            adapter->onCall(env, onResult, context, data);
        }
    }

    // function createContext()
    static napi_value createContextProperty(napi_env env, napi_callback_info info)
    {
        uint32_t context = tc_create_context();
        return napiUInt32(env, context);
    }

    // function destroyContext(context)
    static napi_value destroyContextProperty(napi_env env, napi_callback_info info)
    {
        size_t argc = 1;
        napi_value args[1];
        NodeJsAdapter* adapter;
        CHECK(napi_get_cb_info(env, info, &argc, args, nullptr, (void**)&adapter));
        auto context = napiGetUInt32(env, args[0]);
        tc_destroy_context(context);
        return napiUndefined(env);
    }

    // function request(context, methodName, paramsJson, onResult)
    static napi_value requestProperty(napi_env env, napi_callback_info info)
    {
        size_t argc = 3;
        napi_value args[3];
        NodeJsAdapter* adapter;
        CHECK(napi_get_cb_info(env, info, &argc, args, nullptr, (void**)&adapter));
        adapter->request(env, argc, args);
        return napiUndefined(env);
    }

    static napi_value initHandler(napi_env env, napi_value exports)
    {
        shared = new NodeJsAdapter;
        napi_property_descriptor exportsProperties[3] = {
            { "createContext", nullptr,
                createContextProperty, nullptr,
                nullptr, nullptr,
                napi_default, shared },
            { "destroyContext", nullptr,
                destroyContextProperty, nullptr,
                nullptr, nullptr,
                napi_default, shared },
            { "request", nullptr,
                requestProperty, nullptr,
                nullptr, nullptr,
                napi_default, shared },
        };
        CHECK(napi_define_properties(env, exports, 3, exportsProperties));
        CHECK(napi_wrap(env, exports, shared, unloadHandler, nullptr, nullptr));
        return exports;
    }

    static void unloadHandler(napi_env env, void* data, void* hint)
    {
        auto adapter = shared;
        if (adapter) {
            shared = nullptr;
            delete adapter;
        }
    }

    static NodeJsAdapter* shared;
};

NodeJsAdapter* NodeJsAdapter::shared = nullptr;

NAPI_MODULE(NODE_GYP_MODULE_NAME, NodeJsAdapter::initHandler)
