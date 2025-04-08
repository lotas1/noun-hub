# NounHub Feed Feature

## Purpose
A central place to find school news and announcements quickly.

## Features
- Easy posting and viewing of news, with each post requiring a title and a body.
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
- Only authenticated users can like posts, but only moderators and admins can repost or quote.
- Permissions are managed through user groups (moderators, admins) using "cognito:groups" claim in the access token for all RBAC checks
- Unauthenticated users can view posts and categories, but cannot interact with them

## API Endpoints

### Posts
- `GET /feed/posts` - Get all posts (supports pagination, filtering by category, and sorting) - **Public**
- `GET /feed/posts/{id}` - Get a specific post by ID - **Public**
- `POST /feed/posts` - Create a new post (moderators and admins only) - **Protected**
- `PUT /feed/posts/{id}` - Update an existing post (moderators and admins only) - **Protected**
- `DELETE /feed/posts/{id}` - Delete a post (moderators and admins only) - **Protected**

### Categories
- `GET /feed/categories` - Get all categories - **Public**
- `POST /feed/categories` - Create a new category (moderators and admins only) - **Protected**
- `PUT /feed/categories/{id}` - Update a category (moderators and admins only) - **Protected**
- `DELETE /feed/categories/{id}` - Delete a category (moderators and admins only) - **Protected**

### Likes
- `POST /feed/posts/{id}/like` - Like a post - **Protected**
- `DELETE /feed/posts/{id}/like` - Unlike a post - **Protected**

### Repost
- `POST /feed/posts/{id}/repost` - Repost a post (moderators and admins only) - **Protected**

## Implementation Details

### Database Schema

#### Feed Post Table
- `id` (String, Primary Key): Unique identifier for the post
- `title` (String): Post title
- `body` (String): Post content
- `author_id` (String): ID of the user who created the post
- `category_id` (String): ID of the post's category
- `created_at` (String): Timestamp when the post was created
- `updated_at` (String): Timestamp when the post was last updated
- `likes` (Number): Number of likes the post has received

#### Feed Category Table
- `id` (String, Primary Key): Unique identifier for the category
- `name` (String): Category name
- `created_at` (String): Timestamp when the category was created
- `updated_at` (String): Timestamp when the category was last updated

#### Feed Like Table
- `user_id` (String, Partition Key): ID of the user who liked the post
- `post_id` (String, Sort Key): ID of the liked post
- `created_at` (String): Timestamp when the like was created

### Table Naming Convention
- Feature-specific tables are prefixed with the feature name (e.g., `feed_post_table`)
- This provides clear ownership and prevents naming collisions with other features
- Common resources like the user table remain unprefixed

### Authentication & Authorization
- JWT tokens from AWS Cognito are used for authentication.
- Role-based access control is implemented using Cognito user groups.
- Only users in the "admin" or "moderator" groups can create, edit, or delete posts and categories.
- Admins can modify or delete any content, but moderators cannot modify or delete content created by admins. 