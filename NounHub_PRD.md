# NounHub Product Requirements Document (PRD)

*Product Managers: Marty Cagan & Julie Zhuo*

## Executive Summary

NounHub is a comprehensive mobile platform designed exclusively for the National Open University community. The platform features StudyLab for accessing academic resources, a Feed system for school-related news and information, Forums for structured topic-driven conversations, and NounBuddy - an AI chatbot assistant that helps students with inquiries about school fees, program eligibility, academic calendars, and official FAQs. Through these integrated features, NounHub creates a unified digital ecosystem that enhances the academic experience and builds community within NOUN.

## Product Vision

To create the go-to digital community platform for National Open University students and faculty, enhancing communication, collaboration, and information sharing across departments.

## Philosophy

NounHub is built on the principle of autonomous intelligence and self-sustainability. The platform is designed to work intuitively for all users - undergraduates, postgraduates, aspiring students, and even faculty - without requiring constant intervention or guidance. Like a living ecosystem, NounHub adapts, learns, and evolves based on community interactions, anticipating needs before users themselves recognize them.

Core philosophical tenets:

- **Self-Organization**: The system organizes content and connections organically based on user behavior and emerging patterns.
- **Universal Accessibility**: Every feature is designed to be immediately useful to all community members regardless of their technical proficiency or academic status.
- **Emergent Intelligence**: As more users engage with NounHub, the platform becomes increasingly intuitive, developing capabilities beyond what was explicitly programmed.
- **Minimal Friction**: The interface and experience should feel so natural that users forget they're using technology at all.

This philosophy guides every aspect of NounHub's development, creating a platform that truly "works by itself" - a digital extension of the university community that feels alive and responsive to its members' needs.

## Target Users

- Students enrolled in National Open University programs
- Prospective students seeking enrollment information
- Aspiring applicants exploring university programs and community
- Alumni maintaining connections to the university

## User Metrics & Scale

- Monthly Active Users (MAU): 20,000
- Daily Active Users (DAU): 3,000
- Forum Interactions: 45,000/month
- Data Volume: 225 MB/month, 3.6 million reads/month

## Core Features
### Authentication & Authorization

- Email-based user authentication via AWS Cognito
- User profiles with basic academic information
- Role-Based Access Control (RBAC) implementation:
  - Simple group-based permissions using AWS Cognito groups (moderators, admins)
  - Application-level access control using group claims from JWT tokens
  - Permission validation handled within application logic
- Administrative features:
  - Basic group management for user role assignment

### Feed 
- School-related news and information sharing
- Streamlined post creation and viewing
- Like, repost, and quote functionality
- Chronological feed options

### Forums
- Structured topic-driven conversations with algorithmic content delivery
- Department-specific discussion spaces
- Topic creation and commenting

#### Forum Tabs
- **Popular**: Algorithmic feed prioritizing content based on:
  - Recency: Recent posts receive higher priority
  - Relevance: Content matching user interests based on past interactions
  - Engagement: Posts with higher likes and replies get more visibility

- **Following**: Chronological feed showing posts from followed accounts
  - Reverse chronological order (newest first)
  - Minimal filtering, focused on posting time
  - Content exclusively from followed accounts

- **My Activity**: Unified view of user's forum engagement
  - User-created posts and conversations
  - Comments and replies on other users' posts
  - Chronological display of all user interactions

### StudyLab
- Centralized access to academic resources
- Course materials and study guides
- Digital library integration
- Resource organization and bookmarking

### NounBuddy AI Chatbot
- AI-powered student assistance
- School fees inquiry handling
- Program eligibility information
- Academic calendar access
- Official FAQ integration

## Technical Architecture

### Backend
- **Architecture**: AWS Serverless
- **Framework**: Pulumi with TypeScript
- **User Management**: AWS Cognito with custom group management
- **Authorization**: Role-based access control via Cognito groups

### Mobile
- **Framework**: Flutter (Dart)
- **Platforms**: Android, iOS
- **State Management**: Riverpod
---

For detailed specifications, please refer to the dedicated PRD documents in the backend and mobile directories.