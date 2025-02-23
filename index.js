require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Client } = require('@notionhq/client');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Add this line after creating the Express app
app.set('trust proxy', 1);  // Trust first proxy

// Add logging middleware with masked sensitive info
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    // Mask potentially sensitive URL parameters
    const maskedUrl = req.url.replace(/api_key=[^&]+/, 'api_key=****');
    console.log(`[${new Date().toISOString()}] ${req.method} ${maskedUrl} ${res.statusCode} ${duration}ms`);
  });
  next();
});


// Declare notion client at module scope
let notion;

// Update Notion client initialization logging
try {
  notion = new Client({
    auth: process.env.NOTION_API_KEY,
  });
} catch (error) {
  console.error('Failed to initialize Notion client');
}

// Update buildUserMapping function
function buildUserMapping() {
  const userMappings = process.env.USER_MAPPINGS ? JSON.parse(process.env.USER_MAPPINGS) : {};
  
  if (Object.keys(userMappings).length === 0) {
    console.warn('No user mappings found');
  }
  
  return userMappings;
}

// Initialize user mapping from environment variables
const userMapping = buildUserMapping();

// Update getNotionUserId to be case insensitive
function getNotionUserId(userName) {
  // Convert the input to lowercase for comparison
  const normalizedInput = userName.toLowerCase();
  
  // Find the matching user (case insensitive)
  const matchedUser = Object.keys(userMapping).find(
    name => name.toLowerCase() === normalizedInput
  );
  
  if (!matchedUser) {
    throw new Error('Invalid user');  // Generic error message
  }
  
  return userMapping[matchedUser];
}

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'"],
      connectSrc: ["'self'", "https://api.notion.com"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  referrerPolicy: { policy: 'same-origin' }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Configure CORS more strictly
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'X-API-Key']
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// API Key middleware
function requireApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or missing API key'
    });
  }
  
  next();
}

// Apply the middleware to all routes that need protection
app.use('/api', requireApiKey);  // This protects all /api/* routes
app.use('/health', requireApiKey);  // Protect health check too

// Helper function to get day of week
function getDayOfWeek(date) {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const [year, month, day] = date.split('-').map(Number);
  const dateObj = new Date(year, month - 1, day);
  dateObj.setHours(12, 0, 0, 0);
  return days[dateObj.getDay()];
}

// Update the findExistingEntry function to remove sensitive logging
async function findExistingEntry(date, userId) {
  try {
    const response = await notion.databases.query({
      database_id: process.env.NOTION_DATABASE_ID,
      filter: {
        and: [
          {
            property: 'Date',
            date: {
              equals: date
            }
          },
          {
            property: 'Person',
            people: {
              contains: userId
            }
          }
        ]
      }
    });
    return response.results[0];
  } catch (error) {
    console.error('Error in findExistingEntry');
    throw error;
  }
}

// Update validateTaskInput function
function validateTaskInput(body) {
  const errors = [];
  
  if (!body.date) errors.push('Date is required');
  if (!body.userName) errors.push('User name is required');
  if (!body.category) errors.push('Category is required');
  if (!body.task) errors.push('Task is required');
  
  // Validate date format
  if (body.date && !body.date.match(/^\d{4}-\d{2}-\d{2}$/)) {
    errors.push('Date must be in YYYY-MM-DD format');
  }

  // Validate priority if provided
  const validPriorities = ['DAILY CONSUMPTION', 'MUST', 'TIME PERMITTING'];
  if (body.priority && !validPriorities.includes(body.priority)) {
    errors.push(`Priority must be one of: ${validPriorities.join(', ')}`);
  }
  
  // Add category validation
  const validCategories = ['Work', 'Personal']; // Add your valid categories
  if (!validCategories.includes(body.category)) {
    errors.push(`Category must be one of: ${validCategories.join(', ')}`);
  }
  
  // Add date range validation
  if (body.date) {
    const submissionDate = new Date(body.date);
    const now = new Date();
    const thirtyDaysAgo = new Date(now.setDate(now.getDate() - 30));
    const thirtyDaysAhead = new Date(now.setDate(now.getDate() + 60));
    
    if (submissionDate < thirtyDaysAgo || submissionDate > thirtyDaysAhead) {
      errors.push('Date must be within 30 days of current date');
    }
  }
  
  // Sanitize and validate task content
  if (body.task) {
    // Remove HTML tags and limit length
    const sanitizedTask = body.task
      .replace(/<[^>]*>/g, '') // Remove HTML tags
      .slice(0, 2000); // Reasonable length limit for Notion
    
    if (sanitizedTask !== body.task) {
      errors.push('Task content contains invalid characters');
    }
  }
  
  return errors;
}

// Update the parsing function to preserve rich text objects
function parsePriorityContent(content) {
  // Remove debug logging
  const sections = {
    'DAILY CONSUMPTION': [],
    'MUST': [],
    'TIME PERMITTING': []
  };
  
  let currentSection = null;
  let currentTask = [];
  
  if (!Array.isArray(content)) return sections;
  
  // First pass: identify existing sections
  const existingSections = new Set();
  for (const richText of content) {
    const text = richText.text.content.trim();
    if (Object.keys(sections).includes(text)) {
      existingSections.add(text);
    }
  }
  
  // Second pass: parse content
  for (let i = 0; i < content.length; i++) {
    const richText = content[i];
    const text = richText.text.content;
    
    if (text.trim() === 'DAILY CONSUMPTION' || text.trim() === 'MUST' || text.trim() === 'TIME PERMITTING') {
      if (currentTask.length > 0 && currentSection) {
        sections[currentSection].push(currentTask);
        currentTask = [];
      }
      currentSection = text.trim();
    }
    else if (text.trim() === '') {
      if (currentTask.length > 0 && currentSection) {
        sections[currentSection].push(currentTask);
        currentTask = [];
      }
    }
    else if (currentSection) {
      currentTask.push(richText);
      
      if (i === content.length - 1) {
        sections[currentSection].push(currentTask);
      }
    }
  }
  
  return { sections, existingSections };
}

// Update the formatting function to handle rich text objects
function formatPriorityContent(sections, existingSections, newTaskPriority) {
  // Remove debug logging
  let richTextObjects = [];
  
  const sectionsToProcess = Object.entries(sections)
    .filter(([section, tasks]) => 
      tasks.length > 0 || 
      existingSections.has(section) ||
      (section === newTaskPriority && !existingSections.has(section))
    );
  
  sectionsToProcess.forEach(([section, tasks], sectionIndex) => {
    // Add section header
    richTextObjects.push({
      type: "text",
      text: { content: section + "\n" },
      annotations: { underline: true }
    });
    
    // Add tasks
    tasks.forEach((task, taskIndex) => {
      if (Array.isArray(task)) {
        // Add the task content without extra newline
        richTextObjects.push(...task);
        
        // Add newline after task only if it's not the last task or if there are more sections
        const isLastTask = taskIndex === tasks.length - 1;
        const isLastSection = sectionIndex === sectionsToProcess.length - 1;
        const lastContent = task[task.length - 1]?.text?.content || '';
        
        if (!lastContent.endsWith('\n') && (!isLastTask || !isLastSection)) {
          richTextObjects.push({
            type: "text",
            text: { content: "\n" },
            annotations: {
              bold: false,
              italic: false,
              strikethrough: false,
              underline: false,
              code: false,
              color: "default"
            }
          });
        }
      } else {
        // For string tasks, remove any leading newlines
        const cleanTask = task.replace(/^\n+/, '');
        const isLastTask = taskIndex === tasks.length - 1;
        const isLastSection = sectionIndex === sectionsToProcess.length - 1;
        const taskContent = cleanTask.endsWith('\n') ? cleanTask : 
          ((!isLastTask || !isLastSection) ? cleanTask + '\n' : cleanTask);
        
        richTextObjects.push({
          type: "text",
          text: { content: taskContent },
          annotations: {
            bold: false,
            italic: false,
            strikethrough: false,
            underline: false,
            code: false,
            color: "default"
          }
        });
      }
    });

    // Add extra newline between sections, but not after the last section
    if (sectionIndex < sectionsToProcess.length - 1) {
      richTextObjects.push({
        type: "text",
        text: { content: "\n" },
        annotations: {
          bold: false,
          italic: false,
          strikethrough: false,
          underline: false,
          code: false,
          color: "default"
        }
      });
    }
  });
  
  return richTextObjects;
}

// Add these helper functions for chunking
function validateRichTextContent(richTextBlocks) {
  let totalLength = 0;
  for (const block of richTextBlocks) {
    const content = block?.text?.content || '';
    const url = block?.text?.link?.url || '';
    
    if (content.length > 2000) {
      console.log(`Warning: Text content exceeds 2000 character limit: ${content.length} characters`);
      return false;
    }
    
    if (url && url.length > 2000) {
      console.log(`Warning: URL exceeds 2000 character limit: ${url.length} characters`);
      return false;
    }
    
    totalLength += content.length;
  }
  
  if (totalLength > 2000) {
    console.log(`Warning: Total content exceeds 2000 character limit: ${totalLength} characters`);
    return false;
  }
  
  return true;
}

function chunkRichTextContent(richTextBlocks) {
  const existingSections = new Set();
  const sectionHeaders = {};
  
  for (const block of richTextBlocks) {
    const content = block?.text?.content?.trim() || '';
    if (['DAILY CONSUMPTION', 'MUST', 'TIME PERMITTING'].includes(content)) {
      existingSections.add(content);
      sectionHeaders[content] = block;
    }
  }
  
  const categories = {
    'DAILY CONSUMPTION': [],
    'MUST': [],
    'TIME PERMITTING': []
  };
  
  let currentCategory = null;
  
  for (const block of richTextBlocks) {
    const content = block?.text?.content?.trim() || '';
    
    if (Object.keys(categories).includes(content)) {
      currentCategory = content;
      continue;
    }
    
    if (currentCategory) {
      if (block.text.content.length > 1900) {
        const chunks = block.text.content.match(/.{1,1900}/g) || [];
        chunks.forEach(chunk => {
          categories[currentCategory].push({
            ...block,
            text: { 
              ...block.text,
              content: chunk 
            }
          });
        });
      } else {
        categories[currentCategory].push(block);
      }
    }
  }
  
  const chunks = [];
  let currentChunk = [];
  let currentLength = 0;
  
  for (const category of ['DAILY CONSUMPTION', 'MUST', 'TIME PERMITTING']) {
    if (existingSections.has(category) || categories[category].length > 0) {
      if (currentLength + category.length + 1 > 1900) {
        if (currentChunk.length) {
          chunks.push(currentChunk);
        }
        currentChunk = [];
        currentLength = 0;
      }
      
      const headerBlock = sectionHeaders[category] || {
        type: "text",
        text: { content: `${category}\n` },
        annotations: { underline: true }
      };
      
      currentChunk.push(headerBlock);
      currentLength = category.length + 1;
    }
    
    const tasks = categories[category];
    for (const block of tasks) {
      const blockLength = block.text.content.length;
      
      if (currentLength + blockLength > 1900) {
        if (currentChunk.length) {
          chunks.push(currentChunk);
        }
        currentChunk = [];
        currentLength = 0;
      }
      
      currentChunk.push(block);
      currentLength += blockLength;
    }
  }
  
  if (currentChunk.length) {
    chunks.push(currentChunk);
  }
  
  return chunks;
}

async function updatePagePropertySafely(pageId, propertyName, richTextContent) {
  if (!richTextContent.length) return;
  
  if (validateRichTextContent(richTextContent)) {
    await notion.pages.update({
      page_id: pageId,
      properties: {
        [propertyName]: {
          rich_text: richTextContent
        }
      }
    });
  } else {
    const chunks = chunkRichTextContent(richTextContent);
    let accumulatedContent = [];
    
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      accumulatedContent.push(...chunk);
      
      await notion.pages.update({
        page_id: pageId,
        properties: {
          [propertyName]: {
            rich_text: accumulatedContent
          }
        }
      });
    }
  }
}

// Add near other middleware
const validateJsonBody = (err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      success: false,
      message: 'Invalid JSON payload'
    });
  }
  next();
};

app.use(validateJsonBody);

// Add near other middleware
app.use((req, res, next) => {
  const userAgent = req.headers['user-agent'] || '';
  
  // Block known malicious user agents
  const blockedAgents = ['sqlmap', 'nikto', 'nmap', 'masscan'];
  if (blockedAgents.some(agent => userAgent.toLowerCase().includes(agent))) {
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }
  
  next();
});

// Main endpoint to receive data from Apple Shortcuts
app.post('/api/submit', async (req, res) => {
  try {
    const validationErrors = validateTaskInput(req.body);
    if (validationErrors.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: validationErrors
      });
    }

    const { date, userName, category, priority, task } = req.body;

    let userId;
    try {
      userId = getNotionUserId(userName);
    } catch (error) {
      return res.status(400).json({
        success: false,
        message: error.message
      });
    }

    const day = getDayOfWeek(date);
    const existingEntry = await findExistingEntry(date, userId);

    if (existingEntry) {
      const taskField = `${category} Tasks`;
      const currentContent = existingEntry.properties[taskField]?.rich_text || [];
      
      const { sections, existingSections } = parsePriorityContent(currentContent);
      const section = priority || 'TIME PERMITTING';
      sections[section].push(`- ${task}\n`);
      const updatedContent = formatPriorityContent(sections, existingSections, section);

      try {
        await updatePagePropertySafely(existingEntry.id, taskField, updatedContent);
        res.json({
          success: true,
          message: 'Task appended to existing entry',
          pageId: existingEntry.id,
          url: `https://notion.so/${existingEntry.id.replace(/-/g, '')}`
        });
      } catch (error) {
        throw error;
      }

    } else {
      const taskField = `${category} Tasks`;
      const sections = {
        'DAILY CONSUMPTION': [],
        'MUST': [],
        'TIME PERMITTING': []
      };
      sections[priority || 'TIME PERMITTING'].push(`- ${task}\n`);
      const formattedContent = formatPriorityContent(sections, new Set(), priority || 'TIME PERMITTING');

      const notionPage = {
        parent: {
          database_id: process.env.NOTION_DATABASE_ID,
        },
        properties: {
          'Date': {
            date: {
              start: date
            }
          },
          'Day': {
            select: {
              name: day
            }
          },
          'Person': {
            people: [
              {
                id: userId
              }
            ]
          },
          [taskField]: {
            rich_text: formattedContent
          },
          'Notes': {
            title: [
              {
                text: {
                  content: date
                }
              }
            ]
          }
        }
      };

      try {
        const response = await notion.pages.create(notionPage);
        res.json({
          success: true,
          message: 'New entry created',
          pageId: response.id,
          url: `https://notion.so/${response.id.replace(/-/g, '')}`
        });
      } catch (error) {
        throw error;
      }
    }

  } catch (error) {
    console.error('Error in submission process');
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get available users endpoint
app.get('/api/users', requireApiKey, (req, res) => {
  const users = Object.keys(userMapping);
  res.json({
    success: true,
    users: users
  });
});

// Enhanced health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// Test endpoint to verify Notion connection
app.get('/api/test-notion', async (req, res) => {
  try {
    await notion.databases.retrieve({
      database_id: process.env.NOTION_DATABASE_ID
    });
    res.json({
      success: true,
      message: 'Notion connection successful'
    });
  } catch (error) {
    console.error('Notion connection error');
    res.status(500).json({
      success: false,
      message: 'Error connecting to Notion'
    });
  }
});

// Either remove this endpoint or limit the information returned
app.get('/api/database-info', requireApiKey, async (req, res) => {
  try {
    await notion.databases.retrieve({
      database_id: process.env.NOTION_DATABASE_ID
    });
    
    // Return minimal information
    res.json({
      success: true,
      status: 'connected'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Database connection error'  // Generic error message
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 