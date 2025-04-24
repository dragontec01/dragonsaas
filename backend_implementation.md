# Implementación del Backend con Integraciones API

Este documento detalla la implementación del backend del sistema SaaS similar a DRAGONCEM, incluyendo los modelos de datos, APIs RESTful e integraciones con servicios externos.

## Modelos de Datos

### User.js

```javascript
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['admin', 'manager', 'agent'],
    default: 'agent'
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, { timestamps: true });

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

module.exports = User;
```

### Lead.js

```javascript
const mongoose = require('mongoose');

const leadSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true
  },
  phone: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    trim: true,
    lowercase: true
  },
  source: {
    type: String,
    enum: ['whatsapp', 'call', 'web', 'manual', 'other'],
    default: 'other'
  },
  campaign: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Campaign'
  },
  status: {
    type: String,
    enum: ['new', 'contacted', 'qualified', 'converted', 'lost'],
    default: 'new'
  },
  score: {
    type: Number,
    default: 0
  },
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  lastContact: {
    type: Date
  },
  notes: {
    type: String
  },
  metadata: {
    type: Map,
    of: String
  }
}, { timestamps: true });

const Lead = mongoose.model('Lead', leadSchema);

module.exports = Lead;
```

### Campaign.js

```javascript
const mongoose = require('mongoose');

const campaignSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  type: {
    type: String,
    enum: ['whatsapp', 'call', 'email', 'mixed'],
    default: 'whatsapp'
  },
  status: {
    type: String,
    enum: ['draft', 'active', 'paused', 'completed'],
    default: 'draft'
  },
  startDate: {
    type: Date
  },
  endDate: {
    type: Date
  },
  welcomeMessage: {
    type: String
  },
  agentConfig: {
    initialAgent: {
      type: String,
      enum: ['welcome', 'qualification', 'sales', 'support', 'followup'],
      default: 'welcome'
    },
    agentInstructions: {
      type: Map,
      of: String
    }
  },
  metadata: {
    type: Map,
    of: String
  }
}, { timestamps: true });

const Campaign = mongoose.model('Campaign', campaignSchema);

module.exports = Campaign;
```

### Conversation.js

```javascript
const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  sender: {
    type: String,
    enum: ['user', 'agent', 'system'],
    required: true
  },
  content: {
    type: String,
    required: true
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  metadata: {
    type: Map,
    of: String
  }
});

const conversationSchema = new mongoose.Schema({
  lead: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Lead',
    required: true
  },
  campaign: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Campaign'
  },
  channel: {
    type: String,
    enum: ['whatsapp', 'call', 'web', 'other'],
    default: 'whatsapp'
  },
  status: {
    type: String,
    enum: ['active', 'closed'],
    default: 'active'
  },
  messages: [messageSchema],
  lastMessageAt: {
    type: Date,
    default: Date.now
  },
  metadata: {
    type: Map,
    of: String
  }
}, { timestamps: true });

const Conversation = mongoose.model('Conversation', conversationSchema);

module.exports = Conversation;
```

### Call.js

```javascript
const mongoose = require('mongoose');

const callSchema = new mongoose.Schema({
  lead: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Lead',
    required: true
  },
  direction: {
    type: String,
    enum: ['inbound', 'outbound'],
    required: true
  },
  status: {
    type: String,
    enum: ['initiated', 'ringing', 'in-progress', 'completed', 'failed', 'no-answer'],
    default: 'initiated'
  },
  startTime: {
    type: Date
  },
  endTime: {
    type: Date
  },
  duration: {
    type: Number
  },
  recordingUrl: {
    type: String
  },
  twilioSid: {
    type: String
  },
  notes: {
    type: String
  },
  metadata: {
    type: Map,
    of: String
  }
}, { timestamps: true });

const Call = mongoose.model('Call', callSchema);

module.exports = Call;
```

### IntegrationSetting.js

```javascript
const mongoose = require('mongoose');

const integrationSettingSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  provider: {
    type: String,
    enum: ['gupshup', 'twilio', 'openai', 'other'],
    required: true
  },
  isActive: {
    type: Boolean,
    default: true
  },
  credentials: {
    type: Map,
    of: String,
    required: true
  },
  config: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  }
}, { timestamps: true });

const IntegrationSetting = mongoose.model('IntegrationSetting', integrationSettingSchema);

module.exports = IntegrationSetting;
```

## Controladores API

### authController.js

```javascript
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Registro de usuario
exports.register = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    
    // Verificar si el usuario ya existe
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }
    
    // Crear nuevo usuario
    const user = new User({
      name,
      email,
      password,
      role
    });
    
    await user.save();
    
    // Generar token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );
    
    res.status(201).json({
      message: 'Usuario registrado exitosamente',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error al registrar usuario', error: error.message });
  }
};

// Inicio de sesión
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Verificar si el usuario existe
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }
    
    // Verificar si la contraseña es correcta
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }
    
    // Verificar si el usuario está activo
    if (!user.isActive) {
      return res.status(401).json({ message: 'Usuario desactivado' });
    }
    
    // Generar token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );
    
    res.status(200).json({
      message: 'Inicio de sesión exitoso',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error al iniciar sesión', error: error.message });
  }
};

// Obtener usuario actual
exports.getCurrentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener usuario', error: error.message });
  }
};
```

### leadController.js

```javascript
const Lead = require('../models/Lead');
const Conversation = require('../models/Conversation');

// Obtener todos los leads
exports.getLeads = async (req, res) => {
  try {
    const { status, source, campaign, page = 1, limit = 10 } = req.query;
    
    // Construir filtro
    const filter = {};
    if (status) filter.status = status;
    if (source) filter.source = source;
    if (campaign) filter.campaign = campaign;
    
    // Ejecutar consulta paginada
    const leads = await Lead.find(filter)
      .populate('assignedTo', 'name email')
      .populate('campaign', 'name')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));
    
    // Contar total de documentos
    const total = await Lead.countDocuments(filter);
    
    res.status(200).json({
      leads,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total
    });
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener leads', error: error.message });
  }
};

// Obtener un lead por ID
exports.getLeadById = async (req, res) => {
  try {
    const lead = await Lead.findById(req.params.id)
      .populate('assignedTo', 'name email')
      .populate('campaign', 'name');
    
    if (!lead) {
      return res.status(404).json({ message: 'Lead no encontrado' });
    }
    
    res.status(200).json({ lead });
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener lead', error: error.message });
  }
};

// Crear un nuevo lead
exports.createLead = async (req, res) => {
  try {
    const { name, phone, email, source, campaign, status, assignedTo, notes, metadata } = req.body;
    
    // Verificar si el lead ya existe por teléfono
    const existingLead = await Lead.findOne({ phone });
    if (existingLead) {
      return res.status(400).json({ message: 'Ya existe un lead con este número de teléfono' });
    }
    
    // Crear nuevo lead
    const lead = new Lead({
      name,
      phone,
      email,
      source,
      campaign,
      status,
      assignedTo,
      notes,
      metadata
    });
    
    await lead.save();
    
    res.status(201).json({
      message: 'Lead creado exitosamente',
      lead
    });
  } catch (error) {
    res.status(500).json({ message: 'Error al crear lead', error: error.message });
  }
};

// Actualizar un lead
exports.updateLead = async (req, res) => {
  try {
    const { name, email, status, score, assignedTo, notes, metadata } = req.body;
    
    const lead = await Lead.findById(req.params.id);
    if (!lead) {
      return res.status(404).json({ message: 'Lead no encontrado' });
    }
    
    // Actualizar campos
    if (name) lead.name = name;
    if (email) lead.email = email;
    if (status) lead.status = status;
    if (score !== undefined) lead.score = score;
    if (assignedTo) lead.assignedTo = assignedTo;
    if (notes) lead.notes = notes;
    if (metadata) lead.metadata = metadata;
    
    // Actualizar fecha de último contacto
    lead.lastContact = new Date();
    
    await lead.save();
    
    res.status(200).json({
      message: 'Lead actualizado exitosamente',
      lead
    });
  } catch (error) {
    res.status(500).json({ message: 'Error al actualizar lead', error: error.message });
  }
};

// Eliminar un lead
exports.deleteLead = async (req, res) => {
  try {
    const lead = await Lead.findById(req.params.id);
    if (!lead) {
      return res.status(404).json({ message: 'Lead no encontrado' });
    }
    
    // Eliminar conversaciones asociadas
    await Conversation.deleteMany({ lead: lead._id });
    
    // Eliminar lead
    await lead.remove();
    
    res.status(200).json({ message: 'Lead eliminado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al eliminar lead', error: error.message });
  }
};
```

## Integraciones con APIs Externas

### Integración con Gupshup (WhatsApp)

#### gupshupService.js

```javascript
const axios = require('axios');
const IntegrationSetting = require('../models/IntegrationSetting');

class GupshupService {
  constructor() {
    this.baseUrl = 'https://api.gupshup.io/sm/api/v1';
    this.credentials = null;
    this.initialized = false;
  }
  
  async initialize() {
    try {
      const integration = await IntegrationSetting.findOne({ 
        provider: 'gupshup',
        isActive: true
      });
      
      if (!integration) {
        throw new Error('No se encontró configuración activa para Gupshup');
      }
      
      this.credentials = {
        apiKey: integration.credentials.get('apiKey'),
        appName: integration.credentials.get('appName')
      };
      
      this.initialized = true;
      console.log('Servicio Gupshup inicializado correctamente');
    } catch (error) {
      console.error('Error al inicializar servicio Gupshup:', error);
      throw error;
    }
  }
  
  async ensureInitialized() {
    if (!this.initialized) {
      await this.initialize();
    }
  }
  
  async sendMessage(phone, message, messageType = 'text') {
    await this.ensureInitialized();
    
    try {
      // Asegurar que el número tenga formato internacional
      const formattedPhone = this.formatPhoneNumber(phone);
      
      const url = `${this.baseUrl}/msg`;
      const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'apikey': this.credentials.apiKey
      };
      
      const data = new URLSearchParams();
      data.append('channel', 'whatsapp');
      data.append('source', this.credentials.appName);
      data.append('destination', formattedPhone);
      
      if (messageType === 'text') {
        data.append('message', JSON.stringify({ type: 'text', text: message }));
      } else if (messageType === 'image') {
        data.append('message', JSON.stringify({
          type: 'image',
          originalUrl: message.url,
          previewUrl: message.previewUrl || message.url,
          caption: message.caption || ''
        }));
      } else if (messageType === 'file') {
        data.append('message', JSON.stringify({
          type: 'file',
          url: message.url,
          filename: message.filename
        }));
      }
      
      const response = await axios.post(url, data, { headers });
      
      return {
        success: true,
        messageId: response.data.messageId,
        response: response.data
      };
    } catch (error) {
      console.error('Error al enviar mensaje por Gupshup:', error);
      return {
        success: false,
        error: error.message,
        details: error.response?.data
      };
    }
  }
  
  async sendTemplate(phone, templateName, params) {
    await this.ensureInitialized();
    
    try {
      const formattedPhone = this.formatPhoneNumber(phone);
      
      const url = `${this.baseUrl}/template/msg`;
      const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'apikey': this.credentials.apiKey
      };
      
      const data = new URLSearchParams();
      data.append('channel', 'whatsapp');
      data.append('source', this.credentials.appName);
      data.append('destination', formattedPhone);
      data.append('template', JSON.stringify({
        id: templateName,
        params
      }));
      
      const response = await axios.post(url, data, { headers });
      
      return {
        success: true,
        messageId: response.data.messageId,
        response: response.data
      };
    } catch (error) {
      console.error('Error al enviar plantilla por Gupshup:', error);
      return {
        success: false,
        error: error.message,
        details: error.response?.data
      };
    }
  }
  
  // Webhook para recibir mensajes
  handleWebhook(payload) {
    try {
      // Verificar si es un mensaje de WhatsApp
      if (payload.type !== 'message' || payload.app !== this.credentials?.appName) {
        return { success: false, message: 'Evento no soportado' };
      }
      
      const message = payload.payload.payload;
      const sender = payload.payload.sender.phone;
      
      return {
        success: true,
        data: {
          sender,
          message: message.text || message.url || '',
          type: message.type,
          timestamp: new Date(),
          raw: payload
        }
      };
    } catch (error) {
      console.error('Error al procesar webhook de Gupshup:', error);
      return { success: false, error: error.message };
    }
  }
  
  formatPhoneNumber(phone) {
    // Eliminar espacios, guiones y paréntesis
    let formatted = phone.replace(/[\s\-()]/g, '');
    
    // Asegurar que tenga el formato internacional
    if (!formatted.startsWith('+')) {
      formatted = '+' + formatted;
    }
    
    return formatted;
  }
}

module.exports = new GupshupService();
```

### Integración con Twilio (Llamadas)

#### twilioService.js

```javascript
const twilio = require('twilio');
const IntegrationSetting = require('../models/IntegrationSetting');

class TwilioService {
  constructor() {
    this.client = null;
    this.phoneNumber = null;
    this.initialized = false;
  }
  
  async initialize() {
    try {
      const integration = await IntegrationSetting.findOne({ 
        provider: 'twilio',
        isActive: true
      });
      
      if (!integration) {
        throw new Error('No se encontró configuración activa para Twilio');
      }
      
      const accountSid = integration.credentials.get('accountSid');
      const authToken = integration.credentials.get('authToken');
      this.phoneNumber = integration.credentials.get('phoneNumber');
      
      this.client = twilio(accountSid, authToken);
      this.initialized = true;
      console.log('Servicio Twilio inicializado correctamente');
    } catch (error) {
      console.error('Error al inicializar servicio Twilio:', error);
      throw error;
    }
  }
  
  async ensureInitialized() {
    if (!this.initialized) {
      await this.initialize();
    }
  }
  
  async makeCall(to, options = {}) {
    await this.ensureInitialized();
    
    try {
      const formattedPhone = this.formatPhoneNumber(to);
      
      const callOptions = {
        to: formattedPhone,
        from: this.phoneNumber,
        twiml: options.twiml || '<Response><Say>Hola, esta es una llamada de prueba.</Say></Response>'
      };
      
      // Si se proporciona una URL de webhook, usarla en lugar de TwiML
      if (options.url) {
        delete callOptions.twiml;
        callOptions.url = options.url;
      }
      
      // Opciones adicionales
      if (options.statusCallback) {
        callOptions.statusCallback = options.statusCallback;
        callOptions.statusCallbackEvent = options.statusCallbackEvent || ['initiated', 'ringing', 'answered', 'completed'];
        callOptions.statusCallbackMethod = options.statusCallbackMethod || 'POST';
      }
      
      if (options.recordingEnabled) {
        callOptions.record = true;
        callOptions.recordingStatusCallback = options.recordingStatusCallback;
        callOptions.recordingStatusCallbackMethod = options.recordingStatusCallbackMethod || 'POST';
      }
      
      const call = await this.client.calls.create(callOptions);
      
      return {
        success: true,
        callSid: call.sid,
        status: call.status,
        call
      };
    } catch (error) {
      console.error('Error al realizar llamada con Twilio:', error);
      return {
        success: false,
        error: error.message,
        details: error.response?.data
      };
    }
  }
  
  async getCallStatus(callSid) {
    await this.ensureInitialized();
    
    try {
      const call = await this.client.calls(callSid).fetch();
      
      return {
        success: true,
        status: call.status,
        duration: call.duration,
        call
      };
    } catch (error) {
      console.error('Error al obtener estado de llamada:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  async getRecording(recordingSid) {
    await this.ensureInitialized();
    
    try {
      const recording = await this.client.recordings(recordingSid).fetch();
      
      return {
        success: true,
        duration: recording.duration,
        url: recording.mediaUrl,
        recording
      };
    } catch (error) {
      console.error('Error al obtener grabación:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  // Webhook para eventos de llamadas
  handleCallWebhook(payload) {
    try {
      return {
        success: true,
        data: {
          callSid: payload.CallSid,
          status: payload.CallStatus,
          from: payload.From,
          to: payload.To,
          duration: payload.CallDuration,
          timestamp: new Date(),
          raw: payload
        }
      };
    } catch (error) {
      console.error('Error al procesar webhook de llamada Twilio:', error);
      return { success: false, error: error.message };
    }
  }
  
  // Webhook para eventos de grabación
  handleRecordingWebhook(payload) {
    try {
      return {
        success: true,
        data: {
          callSid: payload.CallSid,
          recordingSid: payload.RecordingSid,
          recordingUrl: payload.RecordingUrl,
          recordingDuration: payload.RecordingDuration,
          timestamp: new Date(),
          raw: payload
        }
      };
    } catch (error) {
      console.error('Error al procesar webhook de grabación Twilio:', error);
      return { success: false, error: error.message };
    }
  }
  
  formatPhoneNumber(phone) {
    // Eliminar espacios, guiones y paréntesis
    let formatted = phone.replace(/[\s\-()]/g, '');
    
    // Asegurar que tenga el formato internacional
    if (!formatted.startsWith('+')) {
      formatted = '+' + formatted;
    }
    
    return formatted;
  }
}

module.exports = new TwilioService();
```

### Integración con OpenAI (Multiagentes)

#### openaiService.js

```javascript
const { OpenAI } = require('openai');
const IntegrationSetting = require('../models/IntegrationSetting');

class OpenAIService {
  constructor() {
    this.client = null;
    this.model = 'gpt-4o';
    this.initialized = false;
  }
  
  async initialize() {
    try {
      const integration = await IntegrationSetting.findOne({ 
        provider: 'openai',
        isActive: true
      });
      
      if (!integration) {
        throw new Error('No se encontró configuración activa para OpenAI');
      }
      
      const apiKey = integration.credentials.get('apiKey');
      this.model = integration.config?.get('model') || 'gpt-4o';
      
      this.client = new OpenAI({ apiKey });
      this.initialized = true;
      console.log('Servicio OpenAI inicializado correctamente');
    } catch (error) {
      console.error('Error al inicializar servicio OpenAI:', error);
      throw error;
    }
  }
  
  async ensureInitialized() {
    if (!this.initialized) {
      await this.initialize();
    }
  }
  
  async generateResponse(messages, options = {}) {
    await this.ensureInitialized();
    
    try {
      const model = options.model || this.model;
      const temperature = options.temperature || 0.7;
      const maxTokens = options.maxTokens || 500;
      
      const response = await this.client.chat.completions.create({
        model,
        messages,
        temperature,
        max_tokens: maxTokens,
        n: 1,
        stream: false
      });
      
      return {
        success: true,
        content: response.choices[0].message.content,
        usage: response.usage,
        response
      };
    } catch (error) {
      console.error('Error al generar respuesta con OpenAI:', error);
      return {
        success: false,
        error: error.message,
        details: error.response?.data
      };
    }
  }
  
  async generateAgentResponse(agentType, conversation, userMessage, options = {}) {
    await this.ensureInitialized();
    
    try {
      // Construir contexto según tipo de agente
      let systemPrompt = '';
      
      switch (agentType) {
        case 'welcome':
          systemPrompt = 'Eres un asistente virtual de bienvenida. Tu objetivo es saludar al usuario de manera amigable, presentar brevemente la empresa y sus servicios, y recopilar información básica como nombre y necesidades principales.';
          break;
        case 'qualification':
          systemPrompt = 'Eres un asistente virtual de calificación de leads. Tu objetivo es evaluar el potencial del lead haciendo preguntas específicas sobre su interés, presupuesto, plazo y autoridad de decisión. Debes ser amable pero directo para obtener información valiosa.';
          break;
        case 'sales':
          systemPrompt = 'Eres un asistente virtual de ventas. Tu objetivo es proporcionar información detallada sobre productos/servicios, responder objeciones, destacar beneficios y guiar al usuario hacia la conversión. Debes ser persuasivo pero no agresivo.';
          break;
        case 'support':
          systemPrompt = 'Eres un asistente virtual de soporte. Tu objetivo es ayudar a resolver problemas, responder preguntas técnicas y proporcionar orientación paso a paso. Debes ser paciente, claro y empático.';
          break;
        case 'followup':
          systemPrompt = 'Eres un asistente virtual de seguimiento. Tu objetivo es reconectar con leads que no han respondido, recordarles la propuesta de valor y motivarlos a retomar la conversación. Debes ser persistente pero respetuoso.';
          break;
        default:
          systemPrompt = 'Eres un asistente virtual amigable y profesional. Tu objetivo es ayudar al usuario de la mejor manera posible.';
      }
      
      // Añadir instrucciones específicas si se proporcionan
      if (options.instructions) {
        systemPrompt += '\n\n' + options.instructions;
      }
      
      // Construir historial de conversación
      const messages = [
        { role: 'system', content: systemPrompt }
      ];
      
      // Añadir mensajes previos de la conversación (limitados a los últimos 10)
      if (conversation && conversation.messages) {
        const recentMessages = conversation.messages
          .slice(-10)
          .map(msg => ({
            role: msg.sender === 'user' ? 'user' : 'assistant',
            content: msg.content
          }));
        
        messages.push(...recentMessages);
      }
      
      // Añadir mensaje actual del usuario
      if (userMessage) {
        messages.push({ role: 'user', content: userMessage });
      }
      
      // Generar respuesta
      return await this.generateResponse(messages, options);
    } catch (error) {
      console.error('Error al generar respuesta de agente:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
}

module.exports = new OpenAIService();
```

## Sistema de Multiagentes

### agentCoordinator.js

```javascript
const Lead = require('../models/Lead');
const Conversation = require('../models/Conversation');
const Campaign = require('../models/Campaign');
const openaiService = require('../services/openaiService');
const gupshupService = require('../services/gupshupService');

class AgentCoordinator {
  constructor() {
    this.agentTypes = ['welcome', 'qualification', 'sales', 'support', 'followup'];
  }
  
  async processIncomingMessage(sender, message, metadata = {}) {
    try {
      // Buscar o crear lead
      let lead = await Lead.findOne({ phone: sender });
      let isNewLead = false;
      
      if (!lead) {
        // Crear nuevo lead
        lead = new Lead({
          phone: sender,
          source: 'whatsapp',
          status: 'new'
        });
        
        // Si viene de una campaña, asociarla
        if (metadata.campaignId) {
          lead.campaign = metadata.campaignId;
        }
        
        await lead.save();
        isNewLead = true;
      }
      
      // Buscar conversación activa o crear una nueva
      let conversation = await Conversation.findOne({ 
        lead: lead._id,
        status: 'active',
        channel: 'whatsapp'
      });
      
      if (!conversation) {
        conversation = new Conversation({
          lead: lead._id,
          campaign: lead.campaign,
          channel: 'whatsapp',
          status: 'active',
          messages: []
        });
      }
      
      // Añadir mensaje del usuario a la conversación
      conversation.messages.push({
        sender: 'user',
        content: message,
        metadata: new Map(Object.entries(metadata))
      });
      
      conversation.lastMessageAt = new Date();
      await conversation.save();
      
      // Determinar qué agente debe responder
      const agentType = await this.determineAgent(lead, conversation, isNewLead);
      
      // Obtener instrucciones específicas para el agente
      const agentInstructions = await this.getAgentInstructions(lead.campaign, agentType);
      
      // Generar respuesta del agente
      const response = await openaiService.generateAgentResponse(
        agentType,
        conversation,
        message,
        { instructions: agentInstructions }
      );
      
      if (!response.success) {
        throw new Error(`Error al generar respuesta: ${response.error}`);
      }
      
      // Añadir respuesta del agente a la conversación
      conversation.messages.push({
        sender: 'agent',
        content: response.content,
        metadata: new Map([['agentType', agentType]])
      });
      
      conversation.lastMessageAt = new Date();
      await conversation.save();
      
      // Enviar respuesta al usuario
      const messageSent = await gupshupService.sendMessage(sender, response.content);
      
      if (!messageSent.success) {
        console.error('Error al enviar mensaje:', messageSent.error);
      }
      
      return {
        success: true,
        lead,
        conversation,
        response: response.content,
        agentType
      };
    } catch (error) {
      console.error('Error en el coordinador de agentes:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  async determineAgent(lead, conversation, isNewLead) {
    try {
      // Si es un lead nuevo, usar agente de bienvenida
      if (isNewLead) {
        return 'welcome';
      }
      
      // Si hay una campaña asociada, verificar configuración
      if (lead.campaign) {
        const campaign = await Campaign.findById(lead.campaign);
        if (campaign && campaign.agentConfig && campaign.agentConfig.initialAgent) {
          return campaign.agentConfig.initialAgent;
        }
      }
      
      // Si hay mensajes previos, analizar la conversación para determinar el mejor agente
      if (conversation.messages.length > 2) {
        // Obtener el último agente que respondió
        const lastAgentMessage = conversation.messages
          .slice()
          .reverse()
          .find(msg => msg.sender === 'agent');
        
        if (lastAgentMessage && lastAgentMessage.metadata.get('agentType')) {
          const lastAgentType = lastAgentMessage.metadata.get('agentType');
          
          // Lógica para cambiar de agente según el contexto
          // Por ejemplo, si el último agente fue 'welcome', pasar a 'qualification'
          if (lastAgentType === 'welcome') {
            return 'qualification';
          }
          
          // Por defecto, mantener el mismo agente
          return lastAgentType;
        }
      }
      
      // Por defecto, usar agente de ventas
      return 'sales';
    } catch (error) {
      console.error('Error al determinar agente:', error);
      return 'sales'; // Agente por defecto en caso de error
    }
  }
  
  async getAgentInstructions(campaignId, agentType) {
    try {
      if (!campaignId) return '';
      
      const campaign = await Campaign.findById(campaignId);
      if (!campaign || !campaign.agentConfig || !campaign.agentConfig.agentInstructions) {
        return '';
      }
      
      return campaign.agentConfig.agentInstructions.get(agentType) || '';
    } catch (error) {
      console.error('Error al obtener instrucciones de agente:', error);
      return '';
    }
  }
}

module.exports = new AgentCoordinator();
```

## Rutas API

### routes/index.js

```javascript
const express = require('express');
const authRoutes = require('./authRoutes');
const leadRoutes = require('./leadRoutes');
const campaignRoutes = require('./campaignRoutes');
const conversationRoutes = require('./conversationRoutes');
const callRoutes = require('./callRoutes');
const integrationRoutes = require('./integrationRoutes');
const webhookRoutes = require('./webhookRoutes');

const router = express.Router();

// Rutas públicas
router.use('/auth', authRoutes);
router.use('/webhooks', webhookRoutes);

// Middleware de autenticación para rutas protegidas
const { authenticate } = require('../middleware/auth');
router.use(authenticate);

// Rutas protegidas
router.use('/leads', leadRoutes);
router.use('/campaigns', campaignRoutes);
router.use('/conversations', conversationRoutes);
router.use('/calls', callRoutes);
router.use('/integrations', integrationRoutes);

module.exports = router;
```

### routes/webhookRoutes.js

```javascript
const express = require('express');
const router = express.Router();
const gupshupService = require('../services/gupshupService');
const twilioService = require('../services/twilioService');
const agentCoordinator = require('../agents/agentCoordinator');

// Webhook para mensajes de WhatsApp (Gupshup)
router.post('/gupshup', async (req, res) => {
  try {
    const result = gupshupService.handleWebhook(req.body);
    
    if (!result.success) {
      return res.status(400).json({ message: result.message || 'Error en webhook' });
    }
    
    // Procesar mensaje con el coordinador de agentes
    if (result.data && result.data.sender && result.data.message) {
      agentCoordinator.processIncomingMessage(
        result.data.sender,
        result.data.message,
        { source: 'gupshup', type: result.data.type }
      ).catch(err => console.error('Error al procesar mensaje:', err));
    }
    
    // Responder inmediatamente para cumplir con requisitos de timeout
    res.status(200).json({ status: 'received' });
  } catch (error) {
    console.error('Error en webhook de Gupshup:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// Webhook para eventos de llamadas (Twilio)
router.post('/twilio/call', async (req, res) => {
  try {
    const result = twilioService.handleCallWebhook(req.body);
    
    if (!result.success) {
      return res.status(400).json({ message: result.message || 'Error en webhook' });
    }
    
    // Aquí se procesaría el evento de llamada
    // Por ejemplo, actualizar el estado de una llamada en la base de datos
    
    // Responder con TwiML si es necesario
    res.set('Content-Type', 'text/xml');
    res.send('<Response></Response>');
  } catch (error) {
    console.error('Error en webhook de llamada Twilio:', error);
    res.status(500).send('<Response></Response>');
  }
});

// Webhook para eventos de grabación (Twilio)
router.post('/twilio/recording', async (req, res) => {
  try {
    const result = twilioService.handleRecordingWebhook(req.body);
    
    if (!result.success) {
      return res.status(400).json({ message: result.message || 'Error en webhook' });
    }
    
    // Aquí se procesaría el evento de grabación
    // Por ejemplo, guardar la URL de la grabación en la base de datos
    
    res.status(200).json({ status: 'received' });
  } catch (error) {
    console.error('Error en webhook de grabación Twilio:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

module.exports = router;
```

## Middleware

### middleware/auth.js

```javascript
const jwt = require('jsonwebtoken');
const User = require('../models/User');

exports.authenticate = async (req, res, next) => {
  try {
    // Verificar si hay token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Acceso no autorizado' });
    }
    
    const token = authHeader.split(' ')[1];
    
    // Verificar token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Verificar si el usuario existe
    const user = await User.findById(decoded.id).select('-password');
    if (!user) {
      return res.status(401).json({ message: 'Usuario no encontrado' });
    }
    
    // Verificar si el usuario está activo
    if (!user.isActive) {
      return res.status(401).json({ message: 'Usuario desactivado' });
    }
    
    // Añadir usuario a la solicitud
    req.user = user;
    next();
  } catch (error) {
    console.error('Error de autenticación:', error);
    res.status(401).json({ message: 'Token inválido' });
  }
};

exports.authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Acceso no autorizado' });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Acceso prohibido' });
    }
    
    next();
  };
};
```

## Configuración Final

### config/database.js

```javascript
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    
    console.log(`MongoDB conectado: ${conn.connection.host}`);
    return conn;
  } catch (error) {
    console.error(`Error al conectar a MongoDB: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
```

### server.js (actualizado)

```javascript
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const dotenv = require('dotenv');
const connectDB = require('./config/database');
const routes = require('./routes');

// Cargar variables de entorno
dotenv.config();

// Inicializar Express
const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// Conectar a MongoDB
connectDB();

// Rutas API
app.use('/api', routes);

// Ruta de estado
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date() });
});

// Manejo de rutas no encontradas
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Ruta no encontrada' });
});

// Manejo global de errores
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    message: 'Error interno del servidor',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Iniciar servidor
const server = app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en el puerto ${PORT}`);
});

// Manejo de cierre graceful
process.on('SIGTERM', () => {
  console.log('SIGTERM recibido, cerrando servidor...');
  server.close(() => {
    console.log('Servidor cerrado');
    process.exit(0);
  });
});

module.exports = { app, server };
```

## Pruebas

### tests/auth.test.js

```javascript
const request = require('supertest');
const mongoose = require('mongoose');
const { app } = require('../src/server');
const User = require('../src/models/User');

describe('Autenticación API', () => {
  beforeAll(async () => {
    // Limpiar usuarios de prueba
    await User.deleteMany({ email: 'test@example.com' });
  });
  
  afterAll(async () => {
    await mongoose.connection.close();
  });
  
  describe('POST /api/auth/register', () => {
    it('debería registrar un nuevo usuario', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Test User',
          email: 'test@example.com',
          password: 'password123',
          role: 'agent'
        });
      
      expect(res.statusCode).toEqual(201);
      expect(res.body).toHaveProperty('token');
      expect(res.body).toHaveProperty('user');
      expect(res.body.user).toHaveProperty('email', 'test@example.com');
    });
    
    it('debería rechazar registro con email duplicado', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Test User 2',
          email: 'test@example.com',
          password: 'password123',
          role: 'agent'
        });
      
      expect(res.statusCode).toEqual(400);
      expect(res.body).toHaveProperty('message', 'El usuario ya existe');
    });
  });
  
  describe('POST /api/auth/login', () => {
    it('debería iniciar sesión con credenciales correctas', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123'
        });
      
      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty('token');
      expect(res.body).toHaveProperty('user');
      expect(res.body.user).toHaveProperty('email', 'test@example.com');
    });
    
    it('debería rechazar inicio de sesión con credenciales incorrectas', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'wrongpassword'
        });
      
      expect(res.statusCode).toEqual(401);
      expect(res.body).toHaveProperty('message', 'Credenciales inválidas');
    });
  });
});
```

## Próximos Pasos

1. Implementar el frontend con React.js
2. Desarrollar la interfaz de configuración
3. Implementar funcionalidades adicionales del sistema multiagente
4. Crear configuraciones de despliegue para entornos de nube y Windows
5. Realizar pruebas exhaustivas del sistema
6. Documentar la solución completa
