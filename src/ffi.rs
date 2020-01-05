#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, dead_code)]

use std::ffi::c_void;
use winapi::um::winnt::{HANDLE, PLARGE_INTEGER, PWSTR, PCWSTR, PSID, PSID_AND_ATTRIBUTES, PTOKEN_GROUPS, PVOID, ACCESS_MASK, PACCESS_MASK, PACL, POBJECT_TYPE_LIST, PACE_HEADER, PSECURITY_DESCRIPTOR};
use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::{BOOL, PBOOL, DWORD, PDWORD, ULONG, USHORT};
use winapi::shared::basetsd::{ULONG64, PULONG64, PLONG64};
use winapi::shared::ntdef::LUID;
use winapi::um::minwinbase::LPTHREAD_START_ROUTINE;

pub const AUTHZ_SKIP_TOKEN_GROUPS: DWORD = 0x2;
pub const AUTHZ_REQUIRE_S4U_LOGON: DWORD = 0x4;
pub const AUTHZ_COMPUTE_PRIVILEGES: DWORD = 0x8;

// Opaque handle types
pub type AUTHZ_ACCESS_CHECK_RESULTS_HANDLE = *const c_void;
pub type AUTHZ_CLIENT_CONTEXT_HANDLE = *const c_void;
pub type AUTHZ_RESOURCE_MANAGER_HANDLE = *const c_void;
pub type AUTHZ_AUDIT_EVENT_HANDLE = *const c_void;
pub type AUTHZ_AUDIT_EVENT_TYPE_HANDLE = *const c_void;
pub type AUTHZ_SECURITY_EVENT_PROVIDER_HANDLE = *const c_void;
pub type AUTHZ_CAP_CHANGE_SUBSCRIPTION_HANDLE = *const c_void;

// Structure defining the access check request.
#[repr(C)]
pub struct AUTHZ_ACCESS_REQUEST  {
    pub DesiredAccess: ACCESS_MASK,
    // To replace the principal self sid in the acl.
    pub PrincipalSelfSid: PSID,
    // Object type list represented by an array of (level, guid) pair and the
    // number of elements in the array. This is a post-fix representation of the
    // object tree.
    // These fields should be set to NULL and 0 respectively except when per
    // property access is desired.
    pub ObjectTypeList: POBJECT_TYPE_LIST,
    pub ObjectTypeListLength: DWORD,
    // To support completely business rules based access. This will be passed as
    // input to the callback access check function. Access check algorithm does
    // not interpret these.
    pub OptionalArguments: PVOID,
}

// Structure to return the results of the access check call.
#[repr(C)]
pub struct AUTHZ_ACCESS_REPLY  {
    // The length of the array representing the object type list structure. If
    // no object type is used to represent the object, then the length must be
    // set to 1.
    // Note: This parameter must be filled!
    pub ResultListLength: DWORD,
    // Array of granted access masks. This memory is allocated by the RM. Access
    // check routines just fill in the values.
    pub GrantedAccessMask: PACCESS_MASK,
    // Array of SACL evaluation results.  This memory is allocated by the RM, if SACL
    // evaluation results are desired. Access check routines just fill in the values.
    // Sacl evaluation will only be performed if auditing is requested.
    pub SaclEvaluationResults: PDWORD,
    // Array of results for each element of the array. This memory is allocated
    // by the RM. Access check routines just fill in the values.
    pub Error: PDWORD
}

// Typedefs for callback functions to be provided by the resource manager.

// Callback access check function takes in
//     AuthzClientContext - a client context
//     pAce - pointer to a callback ace
//     pArgs - Optional arguments that were passed to AuthzAccessCheck thru
//             AuthzAccessRequest->OptionalArguments are passed back here.
//     pbAceApplicable - The resource manager must supply whether the ace should
//         be used in the computation of access evaluation
// Returns
//     TRUE if the API succeeded.
//     FALSE on any intermediate errors (like failed memory allocation)
//         In case of failure, the caller must use SetLastError(ErrorValue).
type FN_AUTHZ_DYNAMIC_ACCESS_CHECK = extern "stdcall" fn(
    hAuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
    pAce: PACE_HEADER,
    pArgs: PVOID,
    pbAceApplicable: PBOOL
) -> BOOL;

// Callback compute dynamic groups function takes in
//     AuthzClientContext - a client context
//     pArgs - Optional arguments that supplied to AuthzInitializeClientContext*
//         thru DynamicGroupArgs are passed back here..
//     pSidAttrArray - To allocate and return an array of (sids, attribute)
//         pairs to be added to the normal part of the client context.
//     pSidCount - Number of elements in pSidAttrArray
//     pRestrictedSidAttrArray - To allocate and return an array of (sids, attribute)
//         pairs to be added to the restricted part of the client context.
//     pRestrictedSidCount - Number of elements in pRestrictedSidAttrArray
// Note:
//    Memory returned thru both these array will be freed by the callback
//    free function defined by the resource manager.
// Returns
//     TRUE if the API succeeded.
//     FALSE on any intermediate errors (like failed memory allocation)
//         In case of failure, the caller must use SetLastError(ErrorValue).
type FN_AUTHZ_COMPUTE_DYNAMIC_GROUPS = extern "stdcall" fn(
    hAuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
    Args: PVOID,
    pSidAttrArray: *mut PSID_AND_ATTRIBUTES,
    pSidCount: PDWORD,
    pRestrictedSidAttrArray: *mut PSID_AND_ATTRIBUTES,
    pRestrictedSidCount: PDWORD
) -> BOOL;

// Callback free function takes in
//     pSidAttrArray - To be freed. This has been allocated by the compute
//     dynamic groups function.
type FN_AUTHZ_FREE_DYNAMIC_GROUPS = extern "stdcall" fn(
    pSidAttrArray: PSID_AND_ATTRIBUTES
);

// Callback central access policy retrieval function takes in
//     AuthzClientContext - a client context
//     capid - CAPID of the central access policy to retrieve.
//     pArgs - Optional arguments that were passed to AuthzAccessCheck through
//         AuthzAccessRequest->OptionalArguments are passed back here.
//     pCentralAccessPolicyApplicable - The resource manager must indicate
//         whether a central access policy should be used in access evaluation.
//     ppCentralAccessPolicy - Pointer to the CAP to be used in the
//         computation of access evaluation. If NULL, the default CAP is applied.
// Returns
//     TRUE if the API succeeded.
//     FALSE on any intermediate errors (like failed memory allocation)
//         In case of failure, the caller must use SetLastError(ErrorValue).
type FN_AUTHZ_GET_CENTRAL_ACCESS_POLICY = extern "stdcall" fn(
    hAuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
    capid: PSID,
    pArgs: PVOID,
    pCentralAccessPolicyApplicable: PBOOL,
    ppCentralAccessPolicy: *mut PVOID,
) -> BOOL;

// Callback central access policy free function takes in
//     pCentralAccessPolicy - To be freed. This memory has been allocated by
//     the central access policy retrieval callback function.
type FN_AUTHZ_FREE_CENTRAL_ACCESS_POLICY = extern "stdcall" fn(
    pCentralAccessPolicy: PVOID
);

// Security attribute data types ...
pub const AUTHZ_SECURITY_ATTRIBUTE_TYPE_INVALID: USHORT = 0x00;
pub const AUTHZ_SECURITY_ATTRIBUTE_TYPE_INT64: USHORT = 0x01;
pub const AUTHZ_SECURITY_ATTRIBUTE_TYPE_UINT64: USHORT = 0x02;

// Case insensitive attribute value string by default.
// Unless the flag AUTHZ_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE
// is set indicating otherwise.
pub const AUTHZ_SECURITY_ATTRIBUTE_TYPE_STRING: USHORT = 0x03;

// Fully-qualified binary name.
#[repr(C)]
pub struct AUTHZ_SECURITY_ATTRIBUTE_FQBN_VALUE {
    pub Version: ULONG64,
    pub pName: PWSTR
}

pub const AUTHZ_SECURITY_ATTRIBUTE_TYPE_FQBN: USHORT = 0x04;
pub const AUTHZ_SECURITY_ATTRIBUTE_TYPE_SID: USHORT = 0x05;
pub const AUTHZ_SECURITY_ATTRIBUTE_TYPE_BOOLEAN: USHORT = 0x06;

// This is the 'catch all' type. The attribute manipulation
// code really doesn't care about the actual format of the
// value. Value subtypes are defined only for this type.
// Value subtypes permit easy addition of new subtypes
// without having to change the attribute manipulation
// (and WOW64 thunking!) code.
#[repr(C)]
pub struct AUTHZ_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE {
    pub pValue: PVOID,        //  Pointer is BYTE aligned.
    pub ValueLength: ULONG    //  In bytes
}

pub const AUTHZ_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING: USHORT = 0x10;

// Attribute operations that can be specified for a 'set' API:
#[repr(C)]
pub enum AUTHZ_SECURITY_ATTRIBUTE_OPERATION {
    //  No-op
    AUTHZ_SECURITY_ATTRIBUTE_OPERATION_NONE = 0,
    //  Delete all existing security attributes and their values in
    //  the NT token and replace it with the specified attributes/values.
    //  If attributes to replace with are not specified, all existing
    //  attributes and values are deleted.
    //  This operation can be specified at most once and must be the
    //  only operation specified.
    AUTHZ_SECURITY_ATTRIBUTE_OPERATION_REPLACE_ALL,
    //  Add a new attribute or a new value to an existing attribute.
    //  If the value specified for any attribute already exists for
    //  that attribute, the call fails.
    AUTHZ_SECURITY_ATTRIBUTE_OPERATION_ADD,
    //  Delete the specified value(s) of the specified attribute(s).
    //  If the last value is deleted from an attribute, the attribute
    //  itself is removed. If no matching attribute name was found, no
    //  modifications are done and the call fails. If no value is specified
    //  for the attribute, the attribute itself will be deleted.
    AUTHZ_SECURITY_ATTRIBUTE_OPERATION_DELETE,
    //  The value(s) of the specified security attribute(s) completely
    //  replace(s) the existing value(s) of the attribute(s). If the
    //  attribute does not already exist, it is added.  When no value
    //  is specified, the attribute is deleted, if it exists; otherwise,
    //  the operation is simply ignored and no failure is reported.
    AUTHZ_SECURITY_ATTRIBUTE_OPERATION_REPLACE
}

// SID operations that can be specified for a 'set' API:
#[repr(C)]
pub enum AUTHZ_SID_OPERATION {
    // No-op
    AUTHZ_SID_OPERATION_NONE = 0,
    // Delete all existing SIDs in the NT token and replace them with
    // the specified SIDs.
    // If the SIDs to replace with are not specified, all existing
    // SIDs are deleted.
    // This operation can be specified at most once and must be the
    // only operation specified.
    AUTHZ_SID_OPERATION_REPLACE_ALL,
    // Add a new SID.
    // If the SID specified already exists, the call fails.
    AUTHZ_SID_OPERATION_ADD,
    // Delete the specified SID(s).
    // If no matching SID was found, no modifications are done and
    // the call fails.
    AUTHZ_SID_OPERATION_DELETE,
    // The specified SID(s) completely replace(s) the existing SID(s).
    // If the SID does not already exist, it is added.
    AUTHZ_SID_OPERATION_REPLACE
}

// An individual security attribute.
#[repr(C)]
pub struct AUTHZ_SECURITY_ATTRIBUTE_V1 {
    // Name of the attribute.
    // Case insensitive Windows Unicode string.
    pub pName: PWSTR,
    //  Data type of attribute.
    pub ValueType: USHORT,
    // Pass 0 in a set operation and check for 0 in
    // a get operation.
    pub Reserved: USHORT,
    pub Flags: ULONG,
    // Number of values.
    pub ValueCount: ULONG,
    // The actual value itself.
    pub Values: AuthzSecurityAttributeV1Values,
}

#[repr(C)]
pub enum AuthzSecurityAttributeV1Values {
    Int64(PLONG64),
    UInt64(PULONG64),
    Utf16(PWSTR),
    FQBN(*mut AUTHZ_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE),
    OctetStrings(*mut AUTHZ_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE),
}

// Attribute must not be inherited across process spawns.
pub const AUTHZ_SECURITY_ATTRIBUTE_NON_INHERITABLE: ULONG = 0x0001;

// Attribute value is compared in a case sensitive way. It is valid with string value
// or composite type containing string value. For other types of value, this flag
// will be ignored. Currently, it is valid with the two types:
// AUTHZ_SECURITY_ATTRIBUTE_TYPE_STRING and AUTHZ_SECURITY_ATTRIBUTE_TYPE_FQBN.
pub const AUTHZ_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE: ULONG = 0x0002;
pub const AUTHZ_SECURITY_ATTRIBUTE_VALID_FLAGS: ULONG = (
    AUTHZ_SECURITY_ATTRIBUTE_NON_INHERITABLE |
    AUTHZ_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE);

// Set of security attributes.
#[repr(C)]
pub struct AUTHZ_SECURITY_ATTRIBUTES_INFORMATION {
    // Versioning. The interpretation of the pointers in the
    // Attribute field below is dependent on the version field.
    // Get operations return the version while the set operation
    // MUST specify the version of the data structure passed in.
    // MUST BE first.
    pub Version: USHORT,
    // Pass 0 in set operations and ignore on get operations.
    pub Reserved: USHORT,
    pub AttributeCount: ULONG,
    pub Attribute: *mut AUTHZ_SECURITY_ATTRIBUTE_V1,
}

pub const AUTHZ_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1: USHORT = 1;
pub const AUTHZ_SECURITY_ATTRIBUTES_INFORMATION_VERSION: USHORT =
    AUTHZ_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1;

// Valid flags for AuthzAccessCheck
pub const AUTHZ_ACCESS_CHECK_NO_DEEP_COPY_SD: DWORD = 0x00000001;

#[link(name="Authz", kind="static")]
extern "stdcall" {
    pub fn AuthzAccessCheck(
        Flags: DWORD,
        hAuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
        pRequest: *mut AUTHZ_ACCESS_REQUEST,
        hAuditEvent: AUTHZ_AUDIT_EVENT_HANDLE,
        pSecurityDescriptor: PSECURITY_DESCRIPTOR,
        OptionalSecurityDescriptorArray: *mut PSECURITY_DESCRIPTOR,
        OptionalSecurityDescriptorCount: DWORD,
        pReply: *mut AUTHZ_ACCESS_REPLY,
        phAccessCheckResults: *mut AUTHZ_ACCESS_CHECK_RESULTS_HANDLE
    ) -> BOOL;

    pub fn AuthzCachedAccessCheck(
        Flags: DWORD,
        hAccessCheckResults: AUTHZ_ACCESS_CHECK_RESULTS_HANDLE,
        pRequest: *mut AUTHZ_ACCESS_REQUEST,
        hAuditEvent: AUTHZ_AUDIT_EVENT_HANDLE,
        pReply: *mut AUTHZ_ACCESS_REPLY
    ) -> BOOL;

    pub fn AuthzOpenObjectAudit(
        Flags: DWORD,
        hAuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
        pRequest: *mut AUTHZ_ACCESS_REQUEST,
        hAuditEvent: AUTHZ_AUDIT_EVENT_HANDLE,
        pSecurityDescriptor: PSECURITY_DESCRIPTOR,
        OptionalSecurityDescriptorArray: *mut PSECURITY_DESCRIPTOR,
        OptionalSecurityDescriptorCount: DWORD,
        pReply: *mut AUTHZ_ACCESS_REPLY
    ) -> BOOL;

    pub fn AuthzFreeHandle(
        hAccessCheckResults: AUTHZ_ACCESS_CHECK_RESULTS_HANDLE
    ) -> BOOL;
}

// Flags for AuthzInitializeResourceManager and AuthzInitializeResourceManagerEx
pub const AUTHZ_RM_FLAG_NO_AUDIT: DWORD = 0x1;
pub const AUTHZ_RM_FLAG_INITIALIZE_UNDER_IMPERSONATION: DWORD = 0x2;
pub const AUTHZ_RM_FLAG_NO_CENTRAL_ACCESS_POLICIES: DWORD = 0x4;
pub const AUTHZ_VALID_RM_INIT_FLAGS: DWORD = (AUTHZ_RM_FLAG_NO_AUDIT |
    AUTHZ_RM_FLAG_INITIALIZE_UNDER_IMPERSONATION |
    AUTHZ_RM_FLAG_NO_CENTRAL_ACCESS_POLICIES);

extern "stdcall" {
    pub fn AuthzInitializeResourceManager(
        Flags: DWORD,
        pfnDynamicAccessCheck: Option<FN_AUTHZ_DYNAMIC_ACCESS_CHECK>,
        pfnComputeDynamicGroups: Option<FN_AUTHZ_COMPUTE_DYNAMIC_GROUPS>,
        pfnFreeDynamicGroups: Option<FN_AUTHZ_FREE_DYNAMIC_GROUPS>,
        szResourceManagerName: PCWSTR,
        phAuthzResourceManager: *mut AUTHZ_RESOURCE_MANAGER_HANDLE
    ) -> BOOL;
}

pub const AUTHZ_RPC_INIT_INFO_CLIENT_VERSION_V1: USHORT = 1;

#[repr(C)]
pub struct AUTHZ_RPC_INIT_INFO_CLIENT
{
    pub version: USHORT,
    pub ObjectUuid: PWSTR,
    pub ProtSeq: PWSTR,
    pub NetworkAddr: PWSTR,
    pub Endpoint: PWSTR,
    pub Options: PWSTR,
    pub ServerSpn: PWSTR,
}

// Versioning enables future updates of authz resource manager initialization
// info structure.
pub const AUTHZ_INIT_INFO_VERSION_V1: USHORT = 1;

// Authz resource manager initialization info structure.
#[repr(C)]
pub struct AUTHZ_INIT_INFO
{
    // authz resource manager initialization info structure version
    pub version: USHORT,
    // the name of the resource manager
    pub szResourceManagerName: PCWSTR,
    // Pointer to the RM supplied access check function to be
    // called when a callback ACE is encountered by the access check algorithm
    pub pfnDynamicAccessCheck: Option<FN_AUTHZ_DYNAMIC_ACCESS_CHECK>,
    // Pointer to the RM supplied function to compute
    // groups to be added to the client context at the time of its creation
    pub pfnComputeDynamicGroups: Option<FN_AUTHZ_COMPUTE_DYNAMIC_GROUPS>,
    // Pointer to the function to free the memory allocated
    // by the pfnComputeDynamicGroups function
    pub pfnFreeDynamicGroups: Option<FN_AUTHZ_FREE_DYNAMIC_GROUPS>,
    // Pointer to the function to be called when
    // a CAPID ACE is encountered by the access check algorithm.
    pub pfnGetCentralAccessPolicy: Option<FN_AUTHZ_GET_CENTRAL_ACCESS_POLICY>,
    // Pointer to the function to free the memory allocated
    // by the pfnGetCentralAccessPolicy function.
    pub pfnFreeCentralAccessPolicy: Option<FN_AUTHZ_FREE_CENTRAL_ACCESS_POLICY>
}

extern "stdcall" {
    pub fn AuthzInitializeResourceManagerEx(
        Flags: DWORD,
        pAuthzInitInfo: *mut AUTHZ_INIT_INFO,
        phAuthzResourceManager: *mut AUTHZ_RESOURCE_MANAGER_HANDLE
    ) -> BOOL;

    pub fn AuthzInitializeRemoteResourceManager(
        pRpcInitInfo: *mut AUTHZ_RPC_INIT_INFO_CLIENT,
        phAuthzResourceManager: *mut AUTHZ_RESOURCE_MANAGER_HANDLE
    ) -> BOOL;

    pub fn AuthzFreeResourceManager(
        hAuthzResourceManager: AUTHZ_RESOURCE_MANAGER_HANDLE
    ) -> BOOL;

    pub fn AuthzInitializeContextFromToken(
        Flags: DWORD,
        TokenHandle: HANDLE,
        hAuthzResourceManager: AUTHZ_RESOURCE_MANAGER_HANDLE,
        pExpirationTime: PLARGE_INTEGER,
        Identifier: LUID,
        DynamicGroupArgs: PVOID,
        phAuthzClientContext: *mut AUTHZ_CLIENT_CONTEXT_HANDLE
    ) -> BOOL;

    pub fn AuthzInitializeContextFromSid(
        Flags: DWORD,
        UserSid: PSID,
        hAuthzResourceManager: AUTHZ_RESOURCE_MANAGER_HANDLE,
        pExpirationTime: PLARGE_INTEGER,
        Identifier: LUID,
        DynamicGroupArgs: PVOID,
        phAuthzClientContext: *mut AUTHZ_CLIENT_CONTEXT_HANDLE
    ) -> BOOL;

    pub fn AuthzInitializeContextFromAuthzContext(
        Flags: DWORD,
        hAuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
        pExpirationTime: PLARGE_INTEGER,
        Identifier: LUID,
        DynamicGroupArgs: PVOID,
        phNewAuthzClientContext: *mut AUTHZ_CLIENT_CONTEXT_HANDLE
    ) -> BOOL;

    pub fn AuthzInitializeCompoundContext(
        UserContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
        DeviceContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
        phCompoundContext: *mut AUTHZ_CLIENT_CONTEXT_HANDLE
    ) -> BOOL;

    pub fn AuthzAddSidsToContext(
        hAuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
        Sids: PSID_AND_ATTRIBUTES,
        SidCount: DWORD,
        RestrictedSids: PSID_AND_ATTRIBUTES,
        RestrictedSidCount: DWORD,
        phNewAuthzClientContext: *mut AUTHZ_CLIENT_CONTEXT_HANDLE
    ) -> BOOL;

    // API to modify security attributes in AUTHZ client context.
    pub fn AuthzModifySecurityAttributes(
        hAuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
        pOperations: *mut AUTHZ_SECURITY_ATTRIBUTE_OPERATION,
        pAttributes: *mut AUTHZ_SECURITY_ATTRIBUTES_INFORMATION
    ) -> BOOL;
}

// Enumeration type to be used to specify the type of information to be
// retrieved from an existing AuthzClientContext.
#[repr(C)]
pub enum AUTHZ_CONTEXT_INFORMATION_CLASS
{
    AuthzContextInfoUserSid = 1,
    AuthzContextInfoGroupsSids,
    AuthzContextInfoRestrictedSids,
    AuthzContextInfoPrivileges,
    AuthzContextInfoExpirationTime,
    AuthzContextInfoServerContext,
    AuthzContextInfoIdentifier,
    AuthzContextInfoSource,
    AuthzContextInfoAll,
    AuthzContextInfoAuthenticationId,
    AuthzContextInfoSecurityAttributes,
    AuthzContextInfoDeviceSids,
    AuthzContextInfoUserClaims,
    AuthzContextInfoDeviceClaims,
    AuthzContextInfoAppContainerSid,
    AuthzContextInfoCapabilitySids
}

extern "stdcall" {
    pub fn AuthzModifyClaims(
        hAuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
        ClaimClass: AUTHZ_CONTEXT_INFORMATION_CLASS,
        pClaimOperations: *mut AUTHZ_SECURITY_ATTRIBUTE_OPERATION,
        pClaims: *mut AUTHZ_SECURITY_ATTRIBUTES_INFORMATION
    ) -> BOOL;

    pub fn AuthzModifySids(
        hAuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
        SidClass: AUTHZ_CONTEXT_INFORMATION_CLASS,
        pSidOperations: *mut AUTHZ_SID_OPERATION,
        pSids: PTOKEN_GROUPS
    ) -> BOOL;

    pub fn AuthzSetAppContainerInformation(
        hAuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
        pAppContainerSid: PSID,
        CapabilityCount: DWORD,
        pCapabilitySids: PSID_AND_ATTRIBUTES,
    ) -> BOOL;

    pub fn AuthzGetInformationFromContext(
        hAuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE,
        InfoClass: AUTHZ_CONTEXT_INFORMATION_CLASS,
        BufferSize: DWORD,
        pSizeRequired: PDWORD,
        Buffer: PVOID
    ) -> BOOL;

    pub fn AuthzFreeContext(
        hAuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE
    ) -> BOOL;
}

// Valid flags that may be used in AuthzInitializeObjectAccessAuditEvent().
pub const AUTHZ_NO_SUCCESS_AUDIT: DWORD = 0x00000001;
pub const AUTHZ_NO_FAILURE_AUDIT: DWORD = 0x00000002;
pub const AUTHZ_NO_ALLOC_STRINGS: DWORD = 0x00000004;
pub const AUTHZ_WPD_CATEGORY_FLAG: DWORD = 0x00000010;
pub const AUTHZ_VALID_OBJECT_ACCESS_AUDIT_FLAGS: DWORD = (AUTHZ_NO_SUCCESS_AUDIT |
    AUTHZ_NO_FAILURE_AUDIT |
    AUTHZ_NO_ALLOC_STRINGS |
    AUTHZ_WPD_CATEGORY_FLAG);

extern "stdcall" {
    /* Variadic stdcall functions are not supported yet
    pub fn AuthzInitializeObjectAccessAuditEvent(
        Flags: DWORD,
        hAuditEventType: AUTHZ_AUDIT_EVENT_TYPE_HANDLE,
        szOperationType: PWSTR,
        szObjectType: PWSTR,
        szObjectName: PWSTR,
        szAdditionalInfo: PWSTR,
        phAuditEvent: *mut AUTHZ_AUDIT_EVENT_HANDLE,
        dwAdditionalParameterCount: DWORD,
        ...
    ) -> BOOL;
    */

    /* Variadic stdcall functions are not supported yet
    pub fn AuthzInitializeObjectAccessAuditEvent2(
        Flags: DWORD,
        hAuditEventType: AUTHZ_AUDIT_EVENT_TYPE_HANDLE,
        szOperationType: PWSTR,
        szObjectType: PWSTR,
        szObjectName: PWSTR,
        szAdditionalInfo: PWSTR,
        szAdditionalInfo2: PWSTR,
        phAuditEvent: *mut AUTHZ_AUDIT_EVENT_HANDLE,
        dwAdditionalParameterCount: DWORD,
        ...
    ) -> BOOL;
    */
}

// Enumeration type to be used to specify the type of information to be
// retrieved from an existing AUTHZ_AUDIT_EVENT_HANDLE.
#[repr(C)]
pub enum AUTHZ_AUDIT_EVENT_INFORMATION_CLASS
{
    AuthzAuditEventInfoFlags = 1,
    AuthzAuditEventInfoOperationType,
    AuthzAuditEventInfoObjectType,
    AuthzAuditEventInfoObjectName,
    AuthzAuditEventInfoAdditionalInfo,
}

extern "stdcall" {
    pub fn AuthzFreeAuditEvent(
        hAuditEvent: AUTHZ_AUDIT_EVENT_HANDLE
    ) -> BOOL;

    // Support for SACL evaluation
    pub fn AuthzEvaluateSacl(
        AuthzClientContext: AUTHZ_CLIENT_CONTEXT_HANDLE ,
        pRequest: *mut AUTHZ_ACCESS_REQUEST,
        Sacl: PACL,
        GrantedAccess: ACCESS_MASK,
        AccessGranted: BOOL,
        pbGenerateAudit: PBOOL
    ) -> BOOL;
}

// Support for generic auditing.
#[repr(C)]
pub struct AUTHZ_REGISTRATION_OBJECT_TYPE_NAME_OFFSET
{
    pub szObjectTypeName: PWSTR,
    pub dwOffset: DWORD
}

#[repr(C)]
pub enum AUTHZ_SOURCE_SCHEMA_REGISTRATION_DATA {
    Reserved(PVOID),
    ProviderGUID(*mut GUID)
}

#[repr(C)]
pub struct AUTHZ_SOURCE_SCHEMA_REGISTRATION
{
    pub dwFlags: DWORD,
    pub szEventSourceName: PWSTR,
    pub szEventMessageFile: PWSTR,
    pub szEventSourceXmlSchemaFile: PWSTR,
    pub szEventAccessStringsFile: PWSTR,
    pub szExecutableImagePath: PWSTR,
    // The meaning of the data is defined by dwFlags. Make sure
    // new types are pointers.
    pub union: AUTHZ_SOURCE_SCHEMA_REGISTRATION_DATA,
    pub dwObjectTypeNameCount: DWORD,
    pub ObjectTypeNames: u8
}

pub const AUTHZ_FLAG_ALLOW_MULTIPLE_SOURCE_INSTANCES: DWORD = 0x1;

extern "stdcall" {
    pub fn AuthzInstallSecurityEventSource(
        dwFlags: DWORD,
        pRegistration: *mut AUTHZ_SOURCE_SCHEMA_REGISTRATION
    ) -> BOOL;

    pub fn AuthzUninstallSecurityEventSource(
        dwFlags: DWORD,
        szEventSourceName: PCWSTR
    ) -> BOOL;

    pub fn AuthzEnumerateSecurityEventSources(
        dwFlags: DWORD,
        Buffer: *mut AUTHZ_SOURCE_SCHEMA_REGISTRATION,
        pdwCount: PDWORD,
        pdwLength: PDWORD
    ) -> BOOL;

    pub fn AuthzRegisterSecurityEventSource(
        dwFlags: DWORD,
        szEventSourceName: PCWSTR,
        phEventProvider: *mut AUTHZ_SECURITY_EVENT_PROVIDER_HANDLE
    ) -> BOOL;

    pub fn AuthzUnregisterSecurityEventSource(
        dwFlags: DWORD,
        phEventProvider: *mut AUTHZ_SECURITY_EVENT_PROVIDER_HANDLE
    ) -> BOOL;

    /* Variadic stdcall functions are not supported yet
    pub fn AuthzReportSecurityEvent(
        dwFlags: DWORD,
        hEventProvider: AUTHZ_SECURITY_EVENT_PROVIDER_HANDLE,
        dwAuditId: DWORD,
        pUserSid: PSID,
        dwCount: DWORD,
        ...
    ) -> BOOL;
    */

    pub fn AuthzReportSecurityEventFromParams(
        dwFlags: DWORD,
        hEventProvider: AUTHZ_SECURITY_EVENT_PROVIDER_HANDLE,
        dwAuditId: DWORD,
        pUserSid: PSID,
        pParams: PVOID
    ) -> BOOL;

    pub fn AuthzRegisterCapChangeNotification(
        phCapChangeSubscription: *mut AUTHZ_CAP_CHANGE_SUBSCRIPTION_HANDLE,
        pfnCapChangeCallback: LPTHREAD_START_ROUTINE,
        pCallbackContext: PVOID
    ) -> BOOL;

    pub fn AuthzUnregisterCapChangeNotification(
        hCapChangeSubscription: AUTHZ_CAP_CHANGE_SUBSCRIPTION_HANDLE
    ) -> BOOL;

    pub fn AuthzFreeCentralAccessPolicyCache() -> BOOL;
}
