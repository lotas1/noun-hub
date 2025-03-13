# NounHub Product Requirements Document (PRD)

*Product Managers: Marty Cagan & Julie Zhuo*

## Executive Summary

NounHub is a mobile application designed for the National Open University community, providing a Twitter-like social experience with department-based forums. The platform enables students and faculty to share posts, engage in discussions, and build community within their academic departments.

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
- Alumni maintaining connections to the university

## User Metrics & Scale

- Monthly Active Users (MAU): 20,000
- Daily Active Users (DAU): 3,000
- Posts: 6,000/day
- Authentication: 90,000 logins/month
- Forum Interactions: 45,000/month
- Data Volume: 225 MB/month, 3.6 million reads/month

## Core Features

### Authentication
- Email-based user authentication via AWS Cognito
- User profiles with basic academic information

### Social Feed
- Twitter-like post creation and viewing
- Like, comment, and share functionality
- Chronological and algorithmic feed options

### Department Forums
- Department-specific discussion spaces
- Topic creation and commenting
- Moderation tools for department administrators

## Technical Architecture

### Backend
- **Architecture**: AWS Serverless
- **Framework**: Pulumi with TypeScript

### Mobile
- **Framework**: Flutter (Dart)
- **Platforms**: Android, iOS
- **State Management**: Riverpod

## Success Metrics

- User Engagement: 15% DAU/MAU ratio
- Content Creation: 0.3 posts per DAU
- Retention: 40% 30-day retention rate
- Forum Participation: 30% of users engaging with forums monthly

## Timeline

### Phase 1 (MVP) - 8 weeks
- Authentication system
- Basic post creation and viewing
- Initial department forum structure

### Phase 2 - 6 weeks
- Enhanced social features (likes, comments)
- Improved forum functionality
- Push notifications

### Phase 3 - 6 weeks
- Advanced search capabilities
- Content moderation tools
- Analytics dashboard for administrators

## Cost Projections

- Initial Scale (20k MAU): ~$8/month
- Medium Scale (50k MAU): ~$25/month
- Large Scale (100k MAU): ~$50/month

---

For detailed specifications, please refer to the dedicated PRD documents in the backend and mobile directories.