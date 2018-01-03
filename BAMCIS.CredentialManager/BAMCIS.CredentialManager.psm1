$script:Code = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace BAMCIS.PowerShell.CredentialManager
{
	/// <summary>
    /// Provides a .NET wrapper around the Win32 CREDENTIAL struct
    /// </summary>
    public class Credential
    {
        #region Private Fields

        private string _Comment;
        private CREDENTIAL_ATTRIBUTE[] _Attributes;
        private string _TargetAlias;
        private string _UserName;

        #endregion

        #region Public Properties

        /// <summary>
        /// A bit member that identifies characteristics of the credential. Undefined bits should be initialized as zero and not otherwise altered to permit future enhancement.
        /// </summary>
        public CredentialFlags Flags { get; set; }

        /// <summary>
        /// The type of the credential. This member cannot be changed after the credential is created.
        /// </summary>
        public CredentialType Type { get; set; }

        /// <summary>
        /// The name of the credential. The TargetName and Type members uniquely identify the credential. This member cannot be changed after the credential is created. Instead, the credential with the old name should be deleted and the credential with the new name created.
        /// </summary>
        public string TargetName { get; private set; }

        /// <summary>
        /// A string comment from the user that describes this credential. This member cannot be longer than CRED_MAX_STRING_LENGTH (256) characters.
        /// </summary>
        public string Comment
        {
            get
            {
                return this._Comment;
            }
            set
            {
                if (!String.IsNullOrEmpty(value))
                {
                    if (value.Length <= 256)
                    {
                        this._Comment = value;
                    }
                    else
                    {
                        throw new ArgumentOutOfRangeException("Comment", "The comment cannot be longer than 256 characters");
                    }
                }
                else
                {
                    this._Comment = String.Empty;
                }
            }
        }

        /// <summary>
        /// The time, in Coordinated Universal Time (Greenwich Mean Time), of the last modification of the credential. For write operations, the value of this member is ignored.
        /// </summary>
        public DateTime LastWritten { get; private set; }

        /// <summary>
        /// Secret data for the credential.
        /// </summary>
        public string CredentialBlob { get; private set; }

        /// <summary>
        /// Defines the persistence of this credential. This member can be read and written.
        /// </summary>
        public CredentialPersistence Persist { get; set; }

        /// <summary>
        /// Application-defined attributes that are associated with the credential. This member can be read and written.
        /// 
        /// This member is not currently supported
        /// </summary>
        public CREDENTIAL_ATTRIBUTE[] Attributes
        {
            get
            {
                return this._Attributes;
            }
            set
            {
                if (value != null)
                {
                    if (value.Length <= 64)
                    {
                        // this._Attributes = value;
                        throw new NotSupportedException("The attributes property is not supported.");
                    }
                    else
                    {
                        throw new ArgumentOutOfRangeException("Attributes", "The number of attributes cannot exceed 64.");
                    }
                }
                else
                {
                    this._Attributes = null;
                }
            }
        }

        /// <summary>
        /// Alias for the TargetName member. This member can be read and written. It cannot be longer than CRED_MAX_STRING_LENGTH (256) characters.
        /// </summary>
        public string TargetAlias
        {
            get
            {
                return this._TargetAlias;
            }
            set
            {
                if (!String.IsNullOrEmpty(value))
                {
                    if (value.Length <= 256)
                    {
                        this._TargetAlias = value;
                    }
                    else
                    {
                        throw new ArgumentOutOfRangeException("TargetAlias", "The TargetAlias cannot exceed 256 characters.");
                    }
                }
                else
                {
                    this._TargetAlias = String.Empty;
                }
            }
        }

        /// <summary>
        /// The user name of the account used to connect to TargetName.
        ///
        /// If the credential Type is CRED_TYPE_DOMAIN_PASSWORD, this member can be either a DomainName\UserName or a UPN.
        ///
        /// If the credential Type is CRED_TYPE_DOMAIN_CERTIFICATE, this member must be a marshaled certificate reference created by calling CredMarshalCredential with a CertCredential.
        ///
        /// If the credential Type is CRED_TYPE_GENERIC, this member can be non-NULL, but the credential manager ignores the member.
        ///
        /// This member cannot be longer than CRED_MAX_USERNAME_LENGTH (513) characters.
        /// </summary>
        public string UserName
        {
            get
            {
                return this._UserName;
            }
            set
            {
                if (!String.IsNullOrEmpty(value))
                {
                    if (value.Length <= 513)
                    {
                        this._UserName = value;
                    }
                    else
                    {
                        throw new ArgumentOutOfRangeException("UserName", "The user name cannot exceed 513 characters.");
                    }
                }
                else
                {
                    this._UserName = String.Empty;
                }
            }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Basic constructor.
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="secret"></param>
        /// <param name="target"></param>
        public Credential(string userName, string secret, string target)
        {
            // XP and Vista: 512; 
            // 7 and above: 5*512
            if (Environment.OSVersion.Version < new Version(6, 1) /* Windows 7 */)
            {
                if (!String.IsNullOrEmpty(secret) && Encoding.Unicode.GetByteCount(secret) > 512)
                {
                    throw new ArgumentOutOfRangeException("secret", "The secret cannot exceed 512 bytes.");
                }
            }
            else
            {
                if (!String.IsNullOrEmpty(secret) && Encoding.Unicode.GetByteCount(secret) > 512 * 5)
                {
                    throw new ArgumentOutOfRangeException("secret", "The secret cannot exceed 2560 bytes.");
                }
            }

            this.CredentialBlob = secret;
            this.UserName = userName;
            this.TargetName = target;

            this.Attributes = null;
            this.Comment = String.Empty;
        }

        /// <summary>
        /// Constructor with credential type.
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="secret"></param>
        /// <param name="target"></param>
        /// <param name="type"></param>
        public Credential(string userName, string secret, string target, CredentialType type) : this(userName, secret, target)
        {
            this.Type = type;
        }

        /// <summary>
        /// Constructor with credential type and persistance.
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="secret"></param>
        /// <param name="target"></param>
        /// <param name="type"></param>
        /// <param name="persist"></param>
        public Credential(string userName, string secret, string target, CredentialType type, CredentialPersistence persist) : this(userName, secret, target, type)
        {
            this.Persist = persist;
        }

        /// <summary>
        /// Constructor with flags.
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="secret"></param>
        /// <param name="target"></param>
        /// <param name="flags"></param>
        public Credential(string userName, string secret, string target, CredentialFlags flags) : this(userName, secret, target)
        {
            this.Flags = flags;
        }

        /// <summary>
        /// Constructor with type and flags.
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="secret"></param>
        /// <param name="target"></param>
        /// <param name="type"></param>
        /// <param name="flags"></param>
        public Credential(string userName, string secret, string target, CredentialType type, CredentialFlags flags) : this(userName, secret, target, type)
        {
            this.Flags = flags;
        }

        /// <summary>
        /// Constructor with type, persistance, and flags.
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="secret"></param>
        /// <param name="target"></param>
        /// <param name="type"></param>
        /// <param name="persist"></param>
        /// <param name="flags"></param>
        public Credential(string userName, string secret, string target, CredentialType type, CredentialPersistence persist, CredentialFlags flags) : this(userName, secret, target, type, persist)
        {
            this.Flags = flags;
        }

        #endregion

        #region Internal Methods

        /// <summary>
        /// Creates a Win32 CREDENTIAL object from this object for writing to Credential Manager
        /// </summary>
        /// <returns></returns>
        internal CREDENTIAL ToWin32Credential()
        {
            CREDENTIAL NewCred = new CREDENTIAL();

            if (this.Attributes == null || this.Attributes.Length == 0)
            {
                NewCred.Attributes = IntPtr.Zero;
                NewCred.AttributeCount = 0;
            }
            else
            {
                // This won't get called, since in this version, the attributes property can't be set
                NewCred.Attributes = Marshal.AllocHGlobal(Marshal.SizeOf(this.Attributes));
                Marshal.StructureToPtr(this.Attributes, NewCred.Attributes, false);
                NewCred.AttributeCount = (UInt32)this.Attributes.Length;
            }

            NewCred.Comment = Marshal.StringToHGlobalUni(this.Comment);
            NewCred.TargetAlias = Marshal.StringToHGlobalUni(this.TargetAlias);
            NewCred.Type = this.Type;
            NewCred.Persist = this.Persist;
            NewCred.TargetName = Marshal.StringToHGlobalUni(this.TargetName);
            NewCred.CredentialBlob = Marshal.StringToHGlobalUni(this.CredentialBlob);
            NewCred.CredentialBlobSize = (UInt32)Encoding.Unicode.GetByteCount(this.CredentialBlob);
            NewCred.UserName = Marshal.StringToHGlobalUni(this.UserName);
			NewCred.Flags = this.Flags;

            return NewCred;
        }

        /// <summary>
        /// Creates a credential object from a marshaled Win32 CREDENTIAL object
        /// </summary>
        /// <param name="credential">The credential object to convert</param>
        /// <returns></returns>
        internal static Credential FromWin32Credential(CREDENTIAL credential)
        {
            string Target = Marshal.PtrToStringUni(credential.TargetName);
            string UserName = Marshal.PtrToStringUni(credential.UserName);
            string Secret = null;

            if (credential.CredentialBlob != IntPtr.Zero)
            {
                Secret = Marshal.PtrToStringUni(credential.CredentialBlob, (int)credential.CredentialBlobSize / 2);
            }

            Credential NewCred = new Credential(UserName, Secret, Target)
            {
                Comment = Marshal.PtrToStringUni(credential.Comment),
                Flags = credential.Flags,
                LastWritten = ToDateTime(credential.LastWritten),
                Persist = credential.Persist,
                TargetAlias = Marshal.PtrToStringUni(credential.TargetAlias),
                Type = credential.Type
            };


            /* This isn't supported yet since the CREDENTIAL_ATTRIBUTE struct isn't necessarily a constant size
            if (credential.Attributes != IntPtr.Zero)
            {
                NewCred.Attributes = new CREDENTIAL_ATTRIBUTE[credential.AttributeCount];

                for (int i = 0; i < credential.AttributeCount; i++)
                {
                    NewCred.Attributes[i] = Marshal.PtrToStructure<CREDENTIAL_ATTRIBUTE>(new IntPtr(credential.Attributes.ToInt64() + i * Marshal.SizeOf<CREDENTIAL_ATTRIBUTE>()));
                }
            }
            */

            return NewCred;
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// https://stackoverflow.com/questions/6083733/not-being-able-to-convert-from-filetime-windows-time-to-datetime-i-get-a-dif
        /// </summary>
        /// <param name="time"></param>
        /// <returns></returns>
        private static DateTime ToDateTime(System.Runtime.InteropServices.ComTypes.FILETIME time)
        {
            UInt64 High = (UInt64)time.dwHighDateTime;
            UInt32 Low = (UInt32)time.dwLowDateTime;

            Int64 fileTime = (Int64)((High << 32) + Low);

            try
            {
                return DateTime.FromFileTimeUtc(fileTime);
            }
            catch (Exception)
            {
                return DateTime.FromFileTimeUtc(0xFFFFFFFF);
            }
        }

        #endregion
    }

	/// <summary>
    /// The CREDENTIAL_ATTRIBUTE structure contains an application-defined attribute of the credential. An attribute is a keyword-value pair. It is up to the application to define the meaning of the attribute.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL_ATTRIBUTE
    {
        /// <summary>
        /// Name of the application-specific attribute. Names should be of the form <CompanyName>_<Name>.
        ///
        /// This member cannot be longer than CRED_MAX_STRING_LENGTH(256) characters.
        /// </summary>
        IntPtr Keyword;

        /// <summary>
        /// Identifies characteristics of the credential attribute. This member is reserved and should be originally initialized as zero and not otherwise altered to permit future enhancement.
        /// </summary>
        UInt32 Flags;

        /// <summary>
        /// Length of Value in bytes. This member cannot be larger than CRED_MAX_VALUE_SIZE (256).
        /// </summary>
        UInt32 ValueSize;

        /// <summary>
        /// Data associated with the attribute. By convention, if Value is a text string, then Value should not include the trailing zero character and should be in UNICODE.
        ///
        /// Credentials are expected to be portable.The application should take care to ensure that the data in value is portable.It is the responsibility of the application to define the byte-endian and alignment of the data in Value.
        /// </summary>
        IntPtr Value;
    }

	/// <summary>
    /// The CREDENTIAL structure contains an individual credential.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL
    {
        /// <summary>
        /// A bit member that identifies characteristics of the credential. Undefined bits should be initialized as zero and not otherwise altered to permit future enhancement.
        /// </summary>
        public CredentialFlags Flags;

        /// <summary>
        /// The type of the credential. This member cannot be changed after the credential is created.
        /// </summary>
        public CredentialType Type;

        /// <summary>
        /// The name of the credential. The TargetName and Type members uniquely identify the credential. This member cannot be changed after the credential is created. Instead, the credential with the old name should be deleted and the credential with the new name created.
        /// </summary>
        public IntPtr TargetName;

        /// <summary>
        /// A string comment from the user that describes this credential. This member cannot be longer than CRED_MAX_STRING_LENGTH (256) characters.
        /// </summary>
        public IntPtr Comment;

        /// <summary>
        /// The time, in Coordinated Universal Time (Greenwich Mean Time), of the last modification of the credential. For write operations, the value of this member is ignored.
        /// </summary>
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;

        /// <summary>
        /// The size, in bytes, of the CredentialBlob member. This member cannot be larger than CRED_MAX_CREDENTIAL_BLOB_SIZE (512) bytes.
        /// </summary>
        public UInt32 CredentialBlobSize;

        /// <summary>
        /// Secret data for the credential. The CredentialBlob member can be both read and written.
        ///
        /// If the Type member is CRED_TYPE_DOMAIN_PASSWORD, this member contains the plaintext Unicode password for UserName.The CredentialBlob and CredentialBlobSize members do not include a trailing zero character.Also, for CRED_TYPE_DOMAIN_PASSWORD, this member can only be read by the authentication packages.
        ///
        /// If the Type member is CRED_TYPE_DOMAIN_CERTIFICATE, this member contains the clear test Unicode PIN for UserName.The CredentialBlob and CredentialBlobSize members do not include a trailing zero character. Also, this member can only be read by the authentication packages.
        ///
        /// If the Type member is CRED_TYPE_GENERIC, this member is defined by the application.
        ///
        /// Credentials are expected to be portable. Applications should ensure that the data in CredentialBlob is portable.The application defines the byte-endian and alignment of the data in CredentialBlob.
        /// </summary>
        public IntPtr CredentialBlob;

        /// <summary>
        /// Defines the persistence of this credential. This member can be read and written.
        /// </summary>
        public CredentialPersistence Persist;

        /// <summary>
        /// The number of application-defined attributes to be associated with the credential. This member can be read and written. Its value cannot be greater than CRED_MAX_ATTRIBUTES (64).
        /// </summary>
        public UInt32 AttributeCount;

        /// <summary>
        /// Application-defined attributes that are associated with the credential. This member can be read and written.
        /// </summary>
        public IntPtr Attributes;

        /// <summary>
        /// Alias for the TargetName member. This member can be read and written. It cannot be longer than CRED_MAX_STRING_LENGTH (256) characters.
        /// </summary>
        public IntPtr TargetAlias;

        /// <summary>
        /// The user name of the account used to connect to TargetName.
        ///
        /// If the credential Type is CRED_TYPE_DOMAIN_PASSWORD, this member can be either a DomainName\UserName or a UPN.
        ///
        /// If the credential Type is CRED_TYPE_DOMAIN_CERTIFICATE, this member must be a marshaled certificate reference created by calling CredMarshalCredential with a CertCredential.
        ///
        /// If the credential Type is CRED_TYPE_GENERIC, this member can be non-NULL, but the credential manager ignores the member.
        ///
        /// This member cannot be longer than CRED_MAX_USERNAME_LENGTH (513) characters.
        /// </summary>
        public IntPtr UserName;
    }

	/// <summary>
    /// A bit member that identifies characteristics of the credential. Undefined bits should be initialized as zero and not otherwise altered to permit future enhancement.
    /// </summary>
    [Flags]
    public enum CredentialFlags : uint
    {
        /// <summary>
        /// Bit set if the credential does not persist the CredentialBlob and the credential has not been written during this logon session. This bit is ignored on input and is set automatically when queried.
        ///
        /// If Type is CRED_TYPE_DOMAIN_CERTIFICATE, the CredentialBlob is not persisted across logon sessions because the PIN of a certificate is very sensitive information. Indeed, when the credential is written to credential manager, the PIN is passed to the CSP associated with the certificate. The CSP will enforce a PIN retention policy appropriate to the certificate.
        ///
        /// If Type is CRED_TYPE_DOMAIN_PASSWORD or CRED_TYPE_DOMAIN_CERTIFICATE, an authentication package always fails an authentication attempt when using credentials marked as CRED_FLAGS_PROMPT_NOW.The application(typically through the key ring UI) prompts the user for the password.The application saves the credential and retries the authentication. Because the credential has been recently written, the authentication package now gets a credential that is not marked as CRED_FLAGS_PROMPT_NOW.
        /// </summary>
        CRED_FLAGS_PROMPT_NOW = 0x2,

        /// <summary>
        /// Bit is set if this credential has a TargetName member set to the same value as the UserName member. Such a credential is one designed to store the CredentialBlob for a specific user. For more information, see the CredMarshalCredential function.
        ///
        /// This bit can only be specified if Type is CRED_TYPE_DOMAIN_PASSWORD or CRED_TYPE_DOMAIN_CERTIFICATE.
        /// </summary>
        CRED_FLAGS_USERNAME_TARGET = 0x4
    }

	/// <summary>
    /// Provides an interface to the Win32 Credential Manager API to read, write, enumerate, and delete stored credentials
    /// </summary>
    public static class CredentialManagerFactory
    {
        #region Win32 Functions

        /// <summary>
        /// The CredRead function reads a credential from the user's credential set. The credential set used is the one associated with the logon session of the current token. The token must not have the user's SID disabled.
        /// </summary>
        /// <param name="targetName">Pointer to a null-terminated string that contains the name of the credential to read.</param>
        /// <param name="type">Type of the credential to read. Type must be one of the CRED_TYPE_* defined types.</param>
        /// <param name="flags">Currently reserved and must be zero.</param>
        /// <param name="credential">Pointer to a single allocated block buffer to return the credential. Any pointers contained within the buffer are pointers to locations within this single allocated block. The single returned buffer must be freed by calling CredFree.</param>
        /// <returns></returns>
        [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredRead(string targetName, CredentialType type, int flags, out IntPtr credential);

        /// <summary>
        /// The CredWrite function creates a new credential or modifies an existing credential in the user's credential set. The new credential is associated with the logon session of the current token. The token must not have the user's security identifier (SID) disabled.
        /// </summary>
        /// <param name="credential">A pointer to the CREDENTIAL structure to be written.</param>
        /// <param name="flags">Flags that control the function's operation. </param>
        /// <returns></returns>
        [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredWrite([In] ref CREDENTIAL credential, [In] UInt32 flags);

        /// <summary>
        /// The CredEnumerate function enumerates the credentials from the user's credential set. The credential set used is the one associated with the logon session of the current token. The token must not have the user's SID disabled.
        /// </summary>
        /// <param name="filter">Pointer to a null-terminated string that contains the filter for the returned credentials. Only credentials with a TargetName matching the filter will be returned. The filter specifies a name prefix followed by an asterisk. For instance, the filter "FRED*" will return all credentials with a TargetName beginning with the string "FRED".
        /// If NULL is specified, all credentials will be returned.</param>
        /// <param name="flag">The value of this parameter can be zero or more of the following values combined with a bitwise-OR operation.</param>
        /// <param name="count">Count of the credentials returned in the Credentials array.</param>
        /// <param name="pCredentials">Pointer to an array of pointers to credentials. The returned credential is a single allocated block. Any pointers contained within the buffer are pointers to locations within this single allocated block. The single returned buffer must be freed by calling CredFree.</param>
        /// <returns></returns>
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredEnumerate(string filter, UInt32 flag, out UInt32 count, out IntPtr pCredentials);

        /// <summary>
        /// The CredFree function frees a buffer returned by any of the credentials management functions.
        /// </summary>
        /// <param name="buffer">Pointer to the buffer to be freed.</param>
        /// <returns></returns>
        [DllImport("advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
        private static extern bool CredFree([In] IntPtr buffer);

        /// <summary>
        /// The CredDelete function deletes a credential from the user's credential set. The credential set used is the one associated with the logon session of the current token. The token must not have the user's SID disabled.
        /// </summary>
        /// <param name="targetName">Pointer to a null-terminated string that contains the name of the credential to delete.</param>
        /// <param name="type">Type of the credential to delete. Must be one of the CRED_TYPE_* defined types. For a list of the defined types, see the Type member of the CREDENTIAL structure.</param>
        /// <param name="flags">Reserved and must be zero.</param>
        /// <returns></returns>
        [DllImport("advapi32.dll", EntryPoint = "CredDelete", SetLastError = true)]
        private static extern bool CredDelete(string targetName, CredentialType type, UInt32 flags);

        private static void ThrowLastWin32Error()
        {
            Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Writes a credential to the Credential Manager Password Vault
        /// </summary>
        /// <param name="credential">The credential to store</param>
        /// <param name="flags">Write flags</param>
        public static void Write(Credential credential, CredWriteFlags flags = 0x0)
        {
            CREDENTIAL NewCred = credential.ToWin32Credential();

            try
            {
                bool Success = CredWrite(ref NewCred, (UInt32)flags);

                if (!Success)
                {
                    int Err = Marshal.GetLastWin32Error();
                    ThrowLastWin32Error();
                }
            }
            finally
            {
                Marshal.FreeHGlobal(NewCred.TargetName);
                Marshal.FreeHGlobal(NewCred.CredentialBlob);
                Marshal.FreeHGlobal(NewCred.UserName);
                Marshal.FreeHGlobal(NewCred.Comment);
                Marshal.FreeHGlobal(NewCred.TargetAlias);
                Marshal.FreeHGlobal(NewCred.Attributes);
            }
        }

        /// <summary>
        /// Reads a credential from the Credential Manager Password Vault
        /// </summary>
        /// <param name="target">The credential target</param>
        /// <param name="type">The credential type</param>
        /// <returns>The stored credential object</returns>
        public static Credential Read(string target, CredentialType type = CredentialType.CRED_TYPE_GENERIC)
        {
            IntPtr CredentialPtr;
            bool Success = CredRead(target, type, 0, out CredentialPtr);

            if (Success)
            {
                CREDENTIAL cred = Marshal.PtrToStructure<CREDENTIAL>(CredentialPtr);
                Credential NewCred = Credential.FromWin32Credential(cred);
                CredFree(CredentialPtr);
                return NewCred;
            }
            else
            {
                ThrowLastWin32Error();
            }

            return null;
        }

        /// <summary>
        /// Deletes a stored credential
        /// </summary>
        /// <param name="target">The credential to delete</param>
        /// <param name="type">The type of the credential</param>
        public static void Delete(string target, CredentialType type = CredentialType.CRED_TYPE_GENERIC)
        {
            bool Success = CredDelete(target, type, 0x0);

            if (!Success)
            {
                ThrowLastWin32Error();
            }
        }

        /// <summary>
        /// Enumerates the credentials from the user's credential set. The credential set used is the one associated with the logon session of the current token. The token must not have the user's SID disabled.
        /// </summary>
        /// <param name="filter">Only credentials with a TargetName matching the filter will be returned. The filter specifies a name prefix followed by an asterisk. For instance, the filter "FRED*" will return all credentials with a TargetName beginning with the string "FRED".
        /// If NULL is specified, all credentials will be returned.</param>
        /// <returns></returns>
        public static IReadOnlyCollection<Credential> Enumerate(string filter)
        {
            return Enumerate(filter, 0x0);
        }

        /// <summary>
        /// Enumerates the credentials from the user's credential set. The credential set used is the one associated with the logon session of the current token. The token must not have the user's SID disabled.
        /// </summary>
        /// <returns></returns>
        public static IReadOnlyCollection<Credential> Enumerate()
        {
            return Enumerate(null, CredEnumerateFlags.CRED_ENUMERATE_ALL_CREDENTIALS);
        }

        #endregion

        #region Private Methods

        private static IReadOnlyCollection<Credential> Enumerate(string filter, CredEnumerateFlags flags = 0x0)
        {
            List<Credential> Results = new List<Credential>();

            UInt32 Count = 0;
            IntPtr Credentials = IntPtr.Zero;

            bool Success = CredEnumerate(filter, (UInt32)flags, out Count, out Credentials);

            if (Success)
            {
                for (int i = 0; i < Count; i++)
                {
                    IntPtr CredPtr = Marshal.ReadIntPtr(Credentials, i * Marshal.SizeOf<IntPtr>());

                    CREDENTIAL Cred = Marshal.PtrToStructure<CREDENTIAL>(CredPtr);

                    Results.Add(Credential.FromWin32Credential(Cred));
                }

                CredFree(Credentials);

                return Results;
            }
            else
            {
                ThrowLastWin32Error();
                return null;
            }
        }

        #endregion
    }

	/// <summary>
    /// Defines the persistence of the credential.
    /// </summary>
    public enum CredentialPersistence : uint
    {
        /// <summary>
        /// The credential persists for the life of the logon session. It will not be visible to other logon sessions of this same user. It will not exist after this user logs off and back on.
        /// </summary>
        CRED_PERSIST_SESSION = 0x1,

        /// <summary>
        /// The credential persists for all subsequent logon sessions on this same computer. It is visible to other logon sessions of this same user on this same computer and not visible to logon sessions for this user on other computers.
        /// </summary>
        CRED_PERSIST_LOCAL_MACHINE = 0x2,

        /// <summary>
        /// The credential persists for all subsequent logon sessions on this same computer. It is visible to other logon sessions of this same user on this same computer and to logon sessions for this user on other computers.
        ///
        /// This option can be implemented as locally persisted credential if the administrator or user configures the user account to not have roam-able state. For instance, if the user has no roaming profile, the credential will only persist locally.
        /// </summary>
        CRED_PERSIST_ENTERPRISE = 0x3
    }

	/// <summary>
    /// The type of the credential. This member cannot be changed after the credential is created. The following values are valid.
    /// </summary>
    public enum CredentialType : uint
    {
        /// <summary>
        /// The credential is a generic credential. The credential will not be used by any particular authentication package. The credential will be stored securely but has no other significant characteristics.
        /// </summary>
        CRED_TYPE_GENERIC = 0x1,

        /// <summary>
        /// The credential is a password credential and is specific to Microsoft's authentication packages. The NTLM, Kerberos, and Negotiate authentication packages will automatically use this credential when connecting to the named target.
        /// </summary>
        CRED_TYPE_DOMAIN_PASSWORD = 0x2,

        /// <summary>
        /// The credential is a certificate credential and is specific to Microsoft's authentication packages. The Kerberos, Negotiate, and Schannel authentication packages automatically use this credential when connecting to the named target.
        /// </summary>
        CRED_TYPE_DOMAIN_CERTIFICATE = 0x3,

        /// <summary>
        /// This value is no longer supported.
        ///
        /// Windows Server 2003 and Windows XP:  The credential is a password credential and is specific to authentication packages from Microsoft. The Passport authentication package will automatically use this credential when connecting to the named target.
        /// </summary>
        CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 0x4,

        /// <summary>
        /// The credential is a certificate credential that is a generic authentication package.
        /// </summary>
        CRED_TYPE_GENERIC_CERTIFICATE = 0x5,

        /// <summary>
        /// The credential is supported by extended Negotiate packages.
        /// </summary>
        CRED_TYPE_DOMAIN_EXTENDED = 0x6,

        /// <summary>
        /// The maximum number of supported credential types.
        /// </summary>
        CRED_TYPE_MAXIMUM = 0x7,

        /// <summary>
        /// The extended maximum number of supported credential types that now allow new applications to run on older operating systems.
        /// </summary>
        CRED_TYPE_MAXIMUM_EX = CRED_TYPE_MAXIMUM + 1000
    }

	/// <summary>
    /// Flags that control the function's operation.
    /// </summary>
    [Flags]
    public enum CredEnumerateFlags : uint
    {
        /// <summary>
        /// This function enumerates all of the credentials in the user's credential set. The target name of each credential is returned in the "namespace:attribute=target" format. If this flag is set and the Filter parameter is not NULL, the function fails and returns ERROR_INVALID_FLAGS.
        /// </summary>
        CRED_ENUMERATE_ALL_CREDENTIALS = 0x1
    }

	/// <summary>
    /// Flags that control the function's operation.
    /// </summary>
    [Flags]
    public enum CredWriteFlags : uint
    {
        /// <summary>
        /// The credential BLOB from an existing credential is preserved with the same credential name and credential type. The CredentialBlobSize of the passed in Credential structure must be zero.
        /// </summary>
        CRED_PRESERVE_CREDENTIAL_BLOB = 0x1
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]"BAMCIS.PowerShell.CredentialManager").Type) 
{
	Add-Type -TypeDefinition $script:Code
}

Function Get-CredManCredential {
	<#
		.SYNOPSIS
			Gets a specified stored credential.

		.DESCRIPTION
			The cmdlet retrieves a stored credential with the specified target name of the specified credential type. If no type is specified, it defaults to generic.

			By default, the cmdlet will only write a warning if the specified credentials are not found. Use ErrorAction to throw an exception if desired.

		.PARAMETER TargetName
			The name of the stored credential.

		.PARAMETER Type
			The type of the stored credential such as CRED_TYPE_GENERIC or CRED_TYPE_DOMAIN_PASSWORD.

		.EXAMPLE
			Get-CredManCredential -TargetName "www.powershellgallery.com"

			This example retrieves the stored GENERIC type credentials for www.powershellgallery.com.

		.EXAMPLE
			Get-CredManCredential -TargetName "fileserver.contoso.com" -Type CRED_TYPE_DOMAIN_PASSWORD -ErrorAction Stop

			This example retrieves the stored DOMAIN credentials for fileserver.contoso.com and throws an exception if they are not found.

		.INPUTS
			None

		.OUTPUTS
			BAMCIS.PowerShell.CredentialManager.Credential

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/3/2018
	#>
	[CmdletBinding()]
	[OutputType([BAMCIS.PowerShell.CredentialManager.Credential])]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$TargetName,

		[Parameter()]
		[ValidateNotNull()]
		[BAMCIS.PowerShell.CredentialManager.CredentialType]$Type = [BAMCIS.PowerShell.CredentialManager.CredentialType]::CRED_TYPE_GENERIC
	)

	Begin {
	}

	Process {
		try
		{
			Write-Output -InputObject ([BAMCIS.PowerShell.CredentialManager.CredentialManagerFactory]::Read($TargetName, $Type))
		}
		catch [Exception]
		{
			if ($ErrorActionPreference -ne [System.Management.Automation.ActionPreference]::Stop)
			{
				Write-Warning -Message $_.Exception.Message
			}
			else
			{
				Write-Error -Exception $_.Exception
			}
		}
	}

	End {
	}
}

Function Set-CredManCredential {
	<#
		.SYNOPSIS
			Creates a new stored credential in Credential Manager or modifies an existing credential.

		.DESCRIPTION
			The cmdlet creates a new stored credential or modifies an existing credential. 

			By default, the cmdlet will only write a warning if the specified credential cannot be created. Use ErrorAction to throw an exception if desired.
		
		.PARAMETER TargetName
			The name of the credential. The TargetName and Type members uniquely identify the credential. This member cannot be changed after the credential is created.

		.PARAMETER UserName
			The user name of the account used to connect to TargetName.

		.PARAMETER Secret
			Secret data for the credential. This can be null or empty. If you are updating an existing credential, this must be empty.

		.PARAMETER Persist
			Defines the persistence of this credential. This defaults to Local Machine.

		.PARAMETER Flags
			A bit member that identifies characteristics of the credential.

			CRED_FLAGS_PROMPT_NOW - Bit set if the credential does not persist the CredentialBlob and the credential has not been written during this logon session. This bit is ignored on input and is set automatically when queried.
			This is only applicable for types CRED_TYPE_DOMAIN_CERTIFICATE or CRED_TYPE_DOMAIN_PASSWORD.

			CRED_FLAGS_USERNAME_TARGET - Bit is set if this credential has a TargetName member set to the same value as the UserName member. Such a credential is one designed to store the CredentialBlob for a specific user.
			This bit can only be specified if Type is CRED_TYPE_DOMAIN_PASSWORD or CRED_TYPE_DOMAIN_CERTIFICATE.

		.PARAMETER WriteFlags
			This cmdlet supports 1 creation flag value, CRED_PRESERVE_CREDENTIAL_BLOB. If this is specified, the cmdlet is used to update an existing credential's
			properties and preserves the existing credential blob. The Secret parameter must be null or empty if this flag is specified.

		.PARAMETER Type
			The type of the credential. This member cannot be changed after the credential is created. 

		.PARAMETER Comment
			A string comment from the user that describes this credential. This member cannot be longer than CRED_MAX_STRING_LENGTH (256) characters.

		.PARAMETER TargetAlias
			Alias for the TargetName member. This member can be read and written. It cannot be longer than CRED_MAX_STRING_LENGTH (256) characters.

		.EXAMPLE
			Set-CredManCredential -TargetName "www.powershellgallery.com" -UserName "john.smith" -Secret "password" -TargetAlias "PSGallery" -Comment "My PS creds"

		.INPUTS
			None

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/3/2018
	#>
	[CmdletBinding()]
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$TargetName,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$UserName,

		[Parameter()]
		[System.String]$Secret = [System.String]::Empty,

		[Parameter()]
		[BAMCIS.PowerShell.CredentialManager.CredentialPersistence]$Persist = [BAMCIS.PowerShell.CredentialManager.CredentialPersistence]::CRED_PERSIST_LOCAL_MACHINE,

		[Parameter()]
		[BAMCIS.PowerShell.CredentialManager.CredWriteFlags]$WriteFlags = 0x0,

		[Parameter()]
		[BAMCIS.PowerShell.CredentialManager.CredentialFlags]$Flags = 0x0,

		[Parameter()]
		[BAMCIS.PowerShell.CredentialManager.CredentialType]$Type = [BAMCIS.PowerShell.CredentialManager.CredentialType]::CRED_TYPE_GENERIC,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateLength(0, 256)]
		[System.String]$Comment,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateLength(0, 256)]
		[System.String]$TargetAlias
	)

	Begin {

	}

	Process {
		[BAMCIS.PowerShell.CredentialManager.Credential]$Cred = New-Object -TypeName BAMCIS.PowerShell.CredentialManager.Credential($UserName, $Secret, $TargetName, $Type, $Persist)

		if (-not [System.String]::IsNullOrEmpty($Comment))
		{
			$Cred.Comment = $Comment
		}

		if (-not [System.String]::IsNullOrEmpty($TargetAlias))
		{
			$Cred.TargetAlias = $TargetAlias
		}

		if ($Flags -ne 0x0)
		{
			$Cred.Flags = $Flags
		}

		if ($WriteFlags -band [BAMCIS.PowerShell.CredentialManager.CredWriteFlags]::CRED_PRESERVE_CREDENTIAL_BLOB)
		{
			if (-not [System.String]::IsNullOrEmpty($Secret))
			{
				throw "When the CRED_PRESERVE_CREDENTIAL_BLOB is specified, the Secret parameter cannot be specified."
			}
		}

		try
		{
			[BAMCIS.PowerShell.CredentialManager.CredentialManagerFactory]::Write($Cred, $WriteFlags)
		}
		catch [Exception]
		{
			if ($ErrorActionPreference -ne [System.Management.Automation.ActionPreference]::Stop)
			{
				Write-Warning -Message $_.Exception.Message
			}
			else
			{
				Write-Error -Exception $_.Exception
			}
		}
	}

	End {

	}
}

Function Get-CredManCredentialList {
	<#
		.SYNOPSIS
			Retrieves a list of credentials associated with the user.

		.DESCRIPTION
			This cmdlet retrieves a list of credentials that match the specified filter. If no filter is specified, all available credentials are retrieved.

		.PARAMETER Filter
			Only credentials with a TargetName matching the filter will be returned. The filter specifies a name prefix followed by an asterisk. For instance, the filter "FRED*" will return all credentials with a TargetName beginning with the string "FRED".

			If a filter is not specified, all credentials are retrieved.
		
		.EXAMPLE
			$Creds = Get-CredManCredentialList

			Retrieves all available credentials.

		.EXAMPLE
			$Creds = Get-CredManCredentialList -Filter "Microsoft*"

			Retrieves all available credentials whose TargetName starts with Microsoft.

		.INPUTS
			System.String

		.OUTPUTS
			BAMCIS.PowerShell.CredentialManager.Credential[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/3/2018
	#>
	[CmdletBinding()]
	[OutputType([BAMCIS.PowerShell.CredentialManager.Credential[]])]
	Param(
		[Parameter(ValueFromPipeline = $true, Position = 0)]
		[System.String]$Filter = $null
	)

	Begin {
	}

	Process {
		try
		{
			if (-not [System.String]::IsNullOrEmpty($Filter))
			{
				Write-Output -InputObject ([BAMCIS.PowerShell.CredentialManager.CredentialManagerFactory]::Enumerate($Filter))
			}
			else
			{
				Write-Output -InputObject ([BAMCIS.PowerShell.CredentialManager.CredentialManagerFactory]::Enumerate())
			}
		}
		catch [Exception]
		{
			if ($ErrorActionPreference -ne [System.Management.Automation.ActionPreference]::Stop)
			{
				Write-Warning -Message $_.Exception.Message
			}
			else
			{
				Write-Error -Exception $_.Exception
			}
		}
	}

	End {
	}
}

Function Remove-CredManCredential {
	<#
		.SYNOPSIS 
			Deletes an existing stored credential.
		
		.DESCRIPTION
			The cmdlet deletes a credential from Credential Manager whose TargetName and Type match the provided parameters. If the Type is not
			specified, it defaults to CRED_TYPE_GENERIC.

		.PARAMETER TargetName
			The target name of the credential to delete.

		.PARAMETER Type
			The type of the credential to delete. This defaults to CRED_TYPE_GENERIC.

		.EXAMPLE
			Remove-CredManCredential -TargetName "outlook.com" -Force

			Removes the credential for outlook.com and bypasses the confirmation prompt.

		.EXAMPLE
			try {
				Remove-CredManCredential -TargetName "google.com" -ErrorAction Stop
			}
			catch [Exception] {
				Write-Host $_.Exception.Message
			}

			This example attempts to remove the google.com credential. If it cannot be deleted or does not exist, the ErrorAction will cause
			an exception to be thrown that can be caught and handled.

		.INPUTS
			None
		
		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/3/2018
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact =  "HIGH")]
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true, Position = 0)]
		[ValidateNotNullOrEmpty()]
		[System.String]$TargetName,

		[Parameter()]
		[ValidateNotNull()]
		[BAMCIS.PowerShell.CredentialManager.CredentialType]$Type = [BAMCIS.PowerShell.CredentialManager.CredentialType]::CRED_TYPE_GENERIC,

		[Parameter()]
		[Switch]$Force
	)

	Begin {
	}

	Process {
		try
		{
			$ConfirmMessage = "Are you sure you want to delete $TargetName`?"

			$WhatIfDescription = "Deleted $TargetName"
			$ConfirmCaption = "Delete Credential"

			if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
			{
				[BAMCIS.PowerShell.CredentialManager.CredentialManagerFactory]::Delete($TargetName, $Type)
			}
		}
		catch [Exception]
		{
			if ($ErrorActionPreference -ne [System.Management.Automation.ActionPreference]::Stop)
			{
				Write-Warning -Message $_.Exception.Message
			}
			else
			{
				Write-Error -Exception $_.Exception
			}
		}
	}

	End {
	}
}