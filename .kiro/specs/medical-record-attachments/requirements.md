# Requirements Document

## Introduction

This document defines the requirements for adding file and image attachment support to the Secure Patient Medical Records backend. Medical records currently store only JSON data (diagnosis, prescription, lab_result, vitals). Healthcare providers need to attach files such as X-ray images, lab scan results, and document photos to patient records. Attachments must maintain the same security posture as existing text records: AES-256-GCM encryption at rest, consent-based access control, role-based permissions, replay attack protection, and append-only audit logging. Files are stored on the local filesystem with a path to support future migration to cloud blob storage.

---

## Glossary

- **System**: The Secure Patient Medical Records backend API.
- **Attachment_Service**: The component responsible for uploading, encrypting, storing, retrieving, decrypting, and deleting file attachments associated with medical records.
- **Attachment**: An encrypted file (image or document) stored on the local filesystem and linked to a specific Medical_Record via a database row.
- **Records_Module**: The existing component that handles CRUD operations on medical records with AES-256 field-level encryption.
- **RBAC_Middleware**: The existing middleware component that enforces role-based access control on every protected endpoint.
- **Consent_Module**: The existing component that manages doctor-initiated access requests and patient approval/revocation.
- **Audit_Module**: The existing component that writes append-only, hash-chained audit log entries.
- **Replay_Guard**: The existing component that validates nonce and timestamp on sensitive endpoints to prevent replay attacks.
- **Key_Manager**: The existing component responsible for loading and providing AES-256 encryption keys from environment configuration.
- **Allowed_MIME_Types**: The set of permitted file content types: image/jpeg, image/png, image/dicom, application/pdf, image/tiff.
- **Max_File_Size**: The maximum permitted file size for a single attachment upload, set to 20 megabytes.
- **Attachment_Storage_Path**: The configurable local filesystem directory where encrypted attachment files are stored.
- **Patient**: A registered user with the Patient role who owns medical records and their attachments.
- **Doctor**: A registered user with the Doctor role who may access attachments on records covered by an active Consent_Grant.
- **Nurse**: A registered user with the Nurse role who has read-only access to attachments on records of Patients under their care.
- **Lab_Technician**: A registered user with the Lab_Technician role who may create and read attachments on lab-result records they created.

---

## Requirements

### Requirement 1: Attachment Upload

**User Story:** As an authorised healthcare provider, I want to upload file attachments to a medical record, so that images and documents such as X-rays and lab scans are stored alongside the patient's clinical data.

#### Acceptance Criteria

1. WHEN an authorised user submits a file upload request with a valid medical record ID, a file whose MIME type is in the Allowed_MIME_Types set, and a file size at or below Max_File_Size, THE Attachment_Service SHALL encrypt the file content using AES-256-GCM, persist the encrypted file to the Attachment_Storage_Path, store the attachment metadata in the database, and return HTTP 201 with the attachment ID and metadata.
2. WHEN an upload request is received with a file whose MIME type is not in the Allowed_MIME_Types set, THE Attachment_Service SHALL return HTTP 422 with a descriptive error message listing the allowed types and SHALL NOT persist any file.
3. WHEN an upload request is received with a file whose size exceeds Max_File_Size, THE Attachment_Service SHALL return HTTP 413 with a descriptive error message stating the maximum allowed size and SHALL NOT persist any file.
4. WHEN an upload request references a medical record ID that does not exist or is soft-deleted, THE Attachment_Service SHALL return HTTP 404.
5. WHEN an upload request is received, THE Attachment_Service SHALL validate the file content bytes against the declared MIME type to prevent MIME type spoofing.
6. THE Attachment_Service SHALL store each encrypted file using a UUID-based filename that does not reveal the original filename, the patient identity, or the record ID.
7. WHEN an attachment is successfully uploaded, THE Audit_Module SHALL append an Audit_Entry with event type ATTACHMENT_UPLOAD containing the actor user ID, the attachment ID, and the associated medical record ID.
8. THE Replay_Guard SHALL apply replay protection to the attachment upload endpoint.

---

### Requirement 2: Attachment Download

**User Story:** As an authorised user, I want to download file attachments from a medical record, so that I can view X-rays, lab scans, and other clinical documents.

#### Acceptance Criteria

1. WHEN an authorised user submits a download request for an existing attachment ID, THE Attachment_Service SHALL read the encrypted file from the Attachment_Storage_Path, decrypt it using AES-256-GCM, and return the plaintext file content with the correct Content-Type header and original filename in the Content-Disposition header.
2. WHEN a download request references an attachment ID that does not exist or belongs to a soft-deleted attachment, THE Attachment_Service SHALL return HTTP 404.
3. WHEN a download request is received, THE Audit_Module SHALL append an Audit_Entry with event type ATTACHMENT_DOWNLOAD containing the actor user ID, the attachment ID, and the associated medical record ID.
4. FOR ALL attachments, uploading a file and then downloading the same attachment SHALL produce file content identical to the original uploaded file (round-trip property).

---

### Requirement 3: Attachment Listing

**User Story:** As an authorised user, I want to list all attachments for a medical record, so that I can see which files are available without downloading each one.

#### Acceptance Criteria

1. WHEN an authorised user submits a list-attachments request with a valid medical record ID, THE Attachment_Service SHALL return HTTP 200 with a list of attachment metadata objects containing: attachment ID, original filename, MIME type, file size in bytes, uploader user ID, and upload timestamp.
2. WHEN a list-attachments request references a medical record ID that does not exist or is soft-deleted, THE Attachment_Service SHALL return HTTP 404.
3. THE Attachment_Service SHALL exclude soft-deleted attachments from the listing response.

---

### Requirement 4: Attachment Deletion

**User Story:** As a Doctor, I want to delete an attachment from a medical record, so that outdated or incorrect files can be removed from the patient's clinical record.

#### Acceptance Criteria

1. WHEN a Doctor with an active Consent_Grant submits a delete request for an existing attachment ID, THE Attachment_Service SHALL soft-delete the attachment record in the database and return HTTP 200.
2. WHEN a user with a role other than Doctor submits a delete request for an attachment, THE Attachment_Service SHALL return HTTP 403.
3. WHEN a delete request references an attachment ID that does not exist or is already soft-deleted, THE Attachment_Service SHALL return HTTP 404.
4. WHEN an attachment is successfully soft-deleted, THE Audit_Module SHALL append an Audit_Entry with event type ATTACHMENT_DELETE containing the actor user ID, the attachment ID, and the associated medical record ID.
5. THE Replay_Guard SHALL apply replay protection to the attachment delete endpoint.

---

### Requirement 5: Attachment Access Control

**User Story:** As a Patient, I want attachment access to follow the same consent-based rules as my medical records, so that only authorised personnel can view my clinical files.

#### Acceptance Criteria

1. WHEN a Patient submits an attachment request (upload, download, list, or delete) for a record that belongs to that Patient, THE Attachment_Service SHALL permit the read operations (download, list) and SHALL deny write operations (upload, delete) with HTTP 403.
2. WHEN a Doctor submits an attachment request for a record belonging to a Patient and an active Consent_Grant exists between the Doctor and the Patient, THE Attachment_Service SHALL permit the request.
3. WHEN a Doctor submits an attachment request for a record belonging to a Patient and no active Consent_Grant exists, THE Attachment_Service SHALL return HTTP 403 with the message "Active consent required".
4. WHEN a Nurse submits an attachment request for a record belonging to a Patient and an active Consent_Grant exists, THE Attachment_Service SHALL permit download and list operations and SHALL deny upload and delete operations with HTTP 403.
5. WHEN a Lab_Technician submits an attachment request for a record, THE Attachment_Service SHALL permit the request only if the Lab_Technician is the creator of the parent medical record, and SHALL deny access with HTTP 403 otherwise.
6. THE Attachment_Service SHALL enforce access control checks before reading any file from the Attachment_Storage_Path to prevent unauthorised file access.

---

### Requirement 6: Attachment Encryption at Rest

**User Story:** As a system operator, I want all attachment files to be encrypted at rest using the same AES-256-GCM scheme as medical record data, so that a filesystem or database breach does not expose patient clinical files in plaintext.

#### Acceptance Criteria

1. WHEN an attachment file is persisted to the Attachment_Storage_Path, THE Attachment_Service SHALL encrypt the entire file content using AES-256-GCM with a unique initialisation vector per file before writing to disk.
2. WHEN an attachment file is retrieved from the Attachment_Storage_Path, THE Attachment_Service SHALL decrypt the file content using AES-256-GCM before returning data to the caller.
3. THE Attachment_Service SHALL store the AES-256-GCM initialisation vector and authentication tag for each attachment in the database alongside the attachment metadata.
4. THE Key_Manager SHALL provide the same RECORD_ENCRYPTION_KEY used for medical record encryption to the Attachment_Service for file encryption.
5. THE Attachment_Service SHALL NOT write plaintext file content to the Attachment_Storage_Path, to temporary files, or to any other persistent storage location at any point during the upload process.
6. FOR ALL attachment files, encrypting the file content and then decrypting the result SHALL produce content identical to the original file bytes (round-trip property).

---

### Requirement 7: Attachment Storage Configuration

**User Story:** As a developer, I want the attachment storage directory to be configurable via environment variables, so that the storage location can be changed without code modifications.

#### Acceptance Criteria

1. THE System SHALL load the Attachment_Storage_Path from an environment variable named ATTACHMENT_STORAGE_PATH.
2. WHEN the System starts and the ATTACHMENT_STORAGE_PATH environment variable is absent, THE System SHALL default to a directory named "attachments" relative to the application working directory.
3. WHEN the System starts and the configured Attachment_Storage_Path directory does not exist, THE System SHALL create the directory with permissions restricted to the application process owner.
4. THE System SHALL load the Max_File_Size from an environment variable named MAX_ATTACHMENT_SIZE_MB, defaulting to 20 megabytes when the variable is absent.
5. THE .env.example file SHALL include entries for ATTACHMENT_STORAGE_PATH and MAX_ATTACHMENT_SIZE_MB with placeholder values and descriptions.

---

### Requirement 8: Attachment Database Model

**User Story:** As a developer, I want attachment metadata stored in a dedicated database table linked to medical records, so that attachments can be queried and managed independently of the encrypted file content.

#### Acceptance Criteria

1. THE System SHALL store attachment metadata in a database table named "attachments" with columns: id (UUID primary key), record_id (foreign key to medical_records), original_filename (string), mime_type (string), file_size_bytes (integer), storage_filename (UUID-based string), iv (binary), tag (binary), uploaded_by (foreign key to users), is_deleted (boolean default false), created_at (timestamp), and updated_at (timestamp).
2. THE System SHALL create a database index on the record_id column of the attachments table to support efficient lookup of attachments by medical record.
3. WHEN a medical record is soft-deleted, THE System SHALL NOT cascade-delete the associated attachments but SHALL exclude them from query results by checking the parent record's is_deleted status.
4. THE System SHALL provide an Alembic migration script to create the attachments table and its indexes.
