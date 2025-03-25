# NounHub Feed Feature

## Purpose
A central place to find school news and announcements quickly.

## Features
- Easy posting and viewing of news, with each post requiring a title and a body.
- Option to include images and files.
- Files include metadata: File Name, File Type, File Size, and Preview Thumbnail (automatically generated for images and documents).
- Users can "Like" posts.
- Only moderators and admins can "Repost" or "Quote" posts.
- Commenting is not allowed.
- Search feature to help users find older posts by keyword.

## Categories
- Posts must be tagged with a category (e.g., TMA, Registration) at creation time.
- Users can sort or filter posts by category.
- Only moderators and admins can create, edit, or delete categories.

## Chronological Viewing
- Users can sort posts by newest to oldest.

## Permissions
- Only admins and moderators can create, edit, or delete posts.
- Admins can edit or delete any post, but moderators can't edit or delete posts made by admins.
- Everyone can like posts, but only moderators and admins can repost or quote.
- Permissions are managed through user groups (moderators, admins) using "cognito:groups" claim in the access token for all RBAC checks

## API Endpoints

### Posts
- `GET /feed/posts` - Get all posts (supports pagination, filtering by category, and sorting)
- `GET /feed/posts/{id}` - Get a specific post by ID
- `POST /feed/posts` - Create a new post (moderators and admins only)
- `PUT /feed/posts/{id}` - Update an existing post (moderators and admins only)
- `DELETE /feed/posts/{id}` - Delete a post (moderators and admins only)

### Categories
- `GET /feed/categories` - Get all categories
- `POST /feed/categories` - Create a new category (moderators and admins only)
- `PUT /feed/categories/{id}` - Update a category (moderators and admins only)
- `DELETE /feed/categories/{id}` - Delete a category (moderators and admins only)

### Likes
- `POST /feed/posts/{id}/like` - Like a post
- `DELETE /feed/posts/{id}/like` - Unlike a post

### Attachments
- `POST /feed/posts/{id}/attachments` - Add an attachment to a post (moderators and admins only)
- `GET /feed/posts/{id}/attachments` - Get all attachments for a post
- `DELETE /feed/attachments/{id}` - Delete an attachment (moderators and admins only)

### Repost
- `POST /feed/posts/{id}/repost` - Repost a post (moderators and admins only)

## Implementation Details

### Database Schema

#### Posts Table
- `id` (String, Primary Key): Unique identifier for the post
- `title` (String): Post title
- `body` (String): Post content
- `author_id` (String): ID of the user who created the post
- `category_id` (String): ID of the post's category
- `created_at` (String): Timestamp when the post was created
- `updated_at` (String): Timestamp when the post was last updated
- `likes` (Number): Number of likes the post has received
- `has_attachment` (Boolean): Whether the post has attachments

#### Categories Table
- `id` (String, Primary Key): Unique identifier for the category
- `name` (String): Category name
- `created_at` (String): Timestamp when the category was created
- `updated_at` (String): Timestamp when the category was last updated

#### Attachments Table
- `id` (String, Primary Key): Unique identifier for the attachment
- `post_id` (String): ID of the post the attachment belongs to
- `file_name` (String): Original file name
- `file_type` (String): MIME type of the file
- `file_size` (Number): Size of the file in bytes
- `s3_key` (String): S3 key where the file is stored
- `has_thumbnail` (Boolean): Whether the attachment has a thumbnail
- `thumbnail_key` (String): S3 key where the thumbnail is stored (if applicable)
- `created_at` (String): Timestamp when the attachment was created

#### Likes Table
- `user_id` (String, Partition Key): ID of the user who liked the post
- `post_id` (String, Sort Key): ID of the liked post
- `created_at` (String): Timestamp when the like was created

### Storage
- Files are stored in an S3 bucket with appropriate permissions.
- Thumbnails are automatically generated for image and document files.

### Authentication & Authorization
- JWT tokens from AWS Cognito are used for authentication.
- Role-based access control is implemented using Cognito user groups.
- Only users in the "admin" or "moderator" groups can create, edit, or delete posts and categories.
- Admins can modify or delete any content, but moderators cannot modify or delete content created by admins. 