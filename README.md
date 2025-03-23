# AI-Powered Phishing Detection System

An intelligent system that combines browser extension and chatbot technologies to detect and analyze phishing URLs.

## Features

- Browser extension with lightweight phishing detection (Random Forest classifier)
- AI chatbot for deep URL analysis (Gradient Boosting classifier)
- Real-time URL analysis and threat scoring
- Educational feedback to users about potential threats

## Architecture

![System Architecture](assets/diagrams/High-Level%20Architectural%20Diagram.png)

## Components

- **Browser Extension**: Provides real-time URL analysis
- **Extension Backend**: Serves the browser extension with API endpoints
- **Chatbot**: Performs deep analysis of suspicious URLs
- **Database**: Stores URLs, analysis results, and system logs

## Setup Instructions

(Instructions will be added as development progresses)

## Tech Stack

- **Frontend**: React.js, Chrome Extensions API, Tailwind CSS
- **Backend**: Python, FastAPI, PostgreSQL
- **AI/ML**: Scikit-learn (Random Forest & Gradient Boosting Classifiers)
- **Infrastructure**: Docker, Google Cloud Platform

## Research

This project is part of a research study on AI-powered phishing detection methods.