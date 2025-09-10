import React, { useState, useEffect } from 'react';
import { Mail, Settings, TestTube, CheckCircle, AlertTriangle, Save, Eye, EyeOff } from 'lucide-react';
import { emailService, EmailConfig, EmailTemplate } from '../services/emailService';

export function EmailAlertConfiguration() {
  const [emailConfig, setEmailConfig] = useState<EmailConfig>({
    id: '',
    name: 'Default Configuration',
    smtpServer: '',
    smtpPort: 587,
    smtpUsername: '',
    smtpPassword: '',
    useTls: true,
    fromEmail: '',
    toEmails: [],
    subjectPrefix: '[SECURITY ALERT]',
    isActive: true,
    thresholds: {
      cpuPercent: 80,
      memoryPercent: 85,
      diskPercent: 90,
      failedLoginThreshold: 5,
      networkScanThreshold: 10,
      checkInterval: 60,
      cooldownPeriod: 300,
      enableThreatDetection: true,
      sendThreatEmails: true,
      criticalIncidentsOnly: false
    }
  });

  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);
  const [toEmailInput, setToEmailInput] = useState('');
  const [templates, setTemplates] = useState<EmailTemplate[]>([]);

  useEffect(() => {
    loadEmailConfiguration();
    loadEmailTemplates();
  }, []);

  const loadEmailConfiguration = async () => {
    try {
      const config = await emailService.getEmailConfiguration();
      if (config) {
        setEmailConfig(config);
      }
    } catch (error) {
      console.error('Failed to load email configuration:', error);
    }
  };

  const loadEmailTemplates = async () => {
    try {
      const templateList = await emailService.getEmailTemplates();
      setTemplates(templateList);
    } catch (error) {
      console.error('Failed to load email templates:', error);
    }
  };

  const handleConfigChange = (field: string, value: any) => {
    if (field.startsWith('thresholds.')) {
      const thresholdField = field.split('.')[1];
      setEmailConfig(prev => ({
        ...prev,
        thresholds: {
          ...prev.thresholds,
          [thresholdField]: value
        }
      }));
    } else {
      setEmailConfig(prev => ({ ...prev, [field]: value }));
    }
    
    // Clear any existing messages when user makes changes
    if (message) setMessage(null);
  };

  const handleAddEmail = () => {
    if (toEmailInput.trim() && !emailConfig.toEmails.includes(toEmailInput.trim())) {
      setEmailConfig(prev => ({
        ...prev,
        toEmails: [...prev.toEmails, toEmailInput.trim()]
      }));
      setToEmailInput('');
    }
  };

  const handleRemoveEmail = (emailToRemove: string) => {
    setEmailConfig(prev => ({
      ...prev,
      toEmails: prev.toEmails.filter(email => email !== emailToRemove)
    }));
  };

  const handleSaveConfiguration = async () => {
    setIsLoading(true);
    setMessage(null);

    try {
      // Validate configuration
      if (!emailConfig.smtpServer || !emailConfig.smtpUsername || !emailConfig.fromEmail) {
        throw new Error('Please fill in all required SMTP fields');
      }

      if (emailConfig.toEmails.length === 0) {
        throw new Error('Please add at least one recipient email address');
      }

      await emailService.saveEmailConfiguration(emailConfig);
      setMessage({ type: 'success', text: 'Email configuration saved successfully!' });
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error instanceof Error ? error.message : 'Failed to save configuration' 
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleTestEmail = async () => {
    setIsTesting(true);
    setMessage(null);

    try {
      const success = await emailService.sendTestEmail(emailConfig);
      if (success) {
        setMessage({ type: 'success', text: 'Test email sent successfully! Check your inbox.' });
      } else {
        setMessage({ type: 'error', text: 'Failed to send test email. Please check your configuration.' });
      }
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error instanceof Error ? error.message : 'Test email failed' 
      });
    } finally {
      setIsTesting(false);
    }
  };

  const handleTestThreatAlert = async () => {
    setIsTesting(true);
    setMessage(null);

    try {
      const success = await emailService.sendThreatAlert({
        threatType: 'test_threat',
        severity: 'medium',
        sourceIp: '192.168.1.100',
        description: 'This is a test cybersecurity threat alert to verify the email system is working correctly.',
        timestamp: new Date(),
        indicators: ['Test indicator 1', 'Test indicator 2'],
        affectedSystems: ['test-system-01']
      }, emailConfig);

      if (success) {
        setMessage({ type: 'success', text: 'Test threat alert sent successfully!' });
      } else {
        setMessage({ type: 'error', text: 'Failed to send test threat alert.' });
      }
    } catch (error) {
      setMessage({ 
        type: 'error', 
        text: error instanceof Error ? error.message : 'Test threat alert failed' 
      });
    } finally {
      setIsTesting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-white flex items-center">
            <Mail className="h-6 w-6 text-blue-400 mr-2" />
            Email Alert Configuration
          </h2>
          <div className="flex items-center space-x-3">
            <button
              onClick={handleTestEmail}
              disabled={isTesting || !emailConfig.smtpServer}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-green-800 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors flex items-center space-x-2"
            >
              <TestTube className="h-4 w-4" />
              <span>{isTesting ? 'Testing...' : 'Test Email'}</span>
            </button>
            <button
              onClick={handleSaveConfiguration}
              disabled={isLoading}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors flex items-center space-x-2"
            >
              <Save className="h-4 w-4" />
              <span>{isLoading ? 'Saving...' : 'Save Configuration'}</span>
            </button>
          </div>
        </div>

        {/* Status Message */}
        {message && (
          <div className={`mb-6 p-4 rounded-lg flex items-center space-x-2 ${
            message.type === 'success' ? 'bg-green-900/30 border border-green-700/50' :
            message.type === 'error' ? 'bg-red-900/30 border border-red-700/50' :
            'bg-blue-900/30 border border-blue-700/50'
          }`}>
            {message.type === 'success' ? (
              <CheckCircle className="h-5 w-5 text-green-400" />
            ) : (
              <AlertTriangle className="h-5 w-5 text-red-400" />
            )}
            <span className={`${
              message.type === 'success' ? 'text-green-300' :
              message.type === 'error' ? 'text-red-300' :
              'text-blue-300'
            }`}>
              {message.text}
            </span>
          </div>
        )}
      </div>

      {/* SMTP Configuration */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
          <Settings className="h-5 w-5 text-gray-400 mr-2" />
          SMTP Server Configuration
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Configuration Name</label>
              <input
                type="text"
                value={emailConfig.name}
                onChange={(e) => handleConfigChange('name', e.target.value)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                placeholder="Default Configuration"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">SMTP Server *</label>
              <input
                type="text"
                value={emailConfig.smtpServer}
                onChange={(e) => handleConfigChange('smtpServer', e.target.value)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                placeholder="smtp.gmail.com"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">SMTP Port</label>
              <input
                type="number"
                value={emailConfig.smtpPort}
                onChange={(e) => handleConfigChange('smtpPort', parseInt(e.target.value))}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                placeholder="587"
                min="1"
                max="65535"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Username *</label>
              <input
                type="email"
                value={emailConfig.smtpUsername}
                onChange={(e) => handleConfigChange('smtpUsername', e.target.value)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                placeholder="your-email@gmail.com"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Password *</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={emailConfig.smtpPassword}
                  onChange={(e) => handleConfigChange('smtpPassword', e.target.value)}
                  className="w-full px-3 py-2 pr-10 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  placeholder="your-app-password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-300"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              <p className="text-xs text-gray-400 mt-1">
                For Gmail, use an App Password instead of your regular password
              </p>
            </div>

            <div>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={emailConfig.useTls}
                  onChange={(e) => handleConfigChange('useTls', e.target.checked)}
                  className="rounded bg-gray-700 border-gray-600 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-sm text-gray-300">Use TLS/SSL encryption</span>
              </label>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">From Email *</label>
              <input
                type="email"
                value={emailConfig.fromEmail}
                onChange={(e) => handleConfigChange('fromEmail', e.target.value)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                placeholder="alerts@yourcompany.com"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Subject Prefix</label>
              <input
                type="text"
                value={emailConfig.subjectPrefix}
                onChange={(e) => handleConfigChange('subjectPrefix', e.target.value)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                placeholder="[SECURITY ALERT]"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Recipient Emails *</label>
              <div className="space-y-2">
                <div className="flex space-x-2">
                  <input
                    type="email"
                    value={toEmailInput}
                    onChange={(e) => setToEmailInput(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleAddEmail()}
                    className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                    placeholder="admin@company.com"
                  />
                  <button
                    type="button"
                    onClick={handleAddEmail}
                    className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                  >
                    Add
                  </button>
                </div>
                
                {emailConfig.toEmails.length > 0 && (
                  <div className="space-y-1">
                    {emailConfig.toEmails.map((email, index) => (
                      <div key={index} className="flex items-center justify-between bg-gray-900 px-3 py-2 rounded">
                        <span className="text-gray-300 text-sm">{email}</span>
                        <button
                          onClick={() => handleRemoveEmail(email)}
                          className="text-red-400 hover:text-red-300 text-xs"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Alert Thresholds */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h3 className="text-lg font-semibold text-white mb-4">Alert Thresholds</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* System Thresholds */}
          <div>
            <h4 className="text-md font-medium text-white mb-3">System Resources</h4>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">CPU Threshold (%)</label>
                <input
                  type="number"
                  value={emailConfig.thresholds.cpuPercent}
                  onChange={(e) => handleConfigChange('thresholds.cpuPercent', parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  min="1" max="100"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Memory Threshold (%)</label>
                <input
                  type="number"
                  value={emailConfig.thresholds.memoryPercent}
                  onChange={(e) => handleConfigChange('thresholds.memoryPercent', parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  min="1" max="100"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Disk Threshold (%)</label>
                <input
                  type="number"
                  value={emailConfig.thresholds.diskPercent}
                  onChange={(e) => handleConfigChange('thresholds.diskPercent', parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  min="1" max="100"
                />
              </div>
            </div>
          </div>

          {/* Security Thresholds */}
          <div>
            <h4 className="text-md font-medium text-white mb-3">Security Thresholds</h4>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Failed Login Threshold</label>
                <input
                  type="number"
                  value={emailConfig.thresholds.failedLoginThreshold}
                  onChange={(e) => handleConfigChange('thresholds.failedLoginThreshold', parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  min="1"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Network Scan Threshold</label>
                <input
                  type="number"
                  value={emailConfig.thresholds.networkScanThreshold}
                  onChange={(e) => handleConfigChange('thresholds.networkScanThreshold', parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  min="1"
                />
              </div>

              <div className="space-y-2">
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={emailConfig.thresholds.enableThreatDetection}
                    onChange={(e) => handleConfigChange('thresholds.enableThreatDetection', e.target.checked)}
                    className="rounded bg-gray-700 border-gray-600 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-sm text-gray-300">Enable threat detection alerts</span>
                </label>
                
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={emailConfig.thresholds.sendThreatEmails}
                    onChange={(e) => handleConfigChange('thresholds.sendThreatEmails', e.target.checked)}
                    className="rounded bg-gray-700 border-gray-600 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-sm text-gray-300">Send threat emails</span>
                </label>
                
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={emailConfig.thresholds.criticalIncidentsOnly}
                    onChange={(e) => handleConfigChange('thresholds.criticalIncidentsOnly', e.target.checked)}
                    className="rounded bg-gray-700 border-gray-600 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-sm text-gray-300">Critical incidents only</span>
                </label>
              </div>
            </div>
          </div>

          {/* Monitoring Settings */}
          <div>
            <h4 className="text-md font-medium text-white mb-3">Monitoring Settings</h4>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Check Interval (seconds)</label>
                <input
                  type="number"
                  value={emailConfig.thresholds.checkInterval}
                  onChange={(e) => handleConfigChange('thresholds.checkInterval', parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  min="30"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Cooldown Period (seconds)</label>
                <input
                  type="number"
                  value={emailConfig.thresholds.cooldownPeriod}
                  onChange={(e) => handleConfigChange('thresholds.cooldownPeriod', parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  min="60"
                />
                <p className="text-xs text-gray-400 mt-1">
                  Minimum time between duplicate alerts
                </p>
              </div>

              <div>
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={emailConfig.isActive}
                    onChange={(e) => handleConfigChange('isActive', e.target.checked)}
                    className="rounded bg-gray-700 border-gray-600 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-sm text-gray-300">Enable email alerts</span>
                </label>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Test Actions */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h3 className="text-lg font-semibold text-white mb-4">Test Email System</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <button
            onClick={handleTestThreatAlert}
            disabled={isTesting || !emailConfig.smtpServer}
            className="px-4 py-3 bg-red-600 hover:bg-red-700 disabled:bg-red-800 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors flex items-center justify-center space-x-2"
          >
            <AlertTriangle className="h-4 w-4" />
            <span>{isTesting ? 'Sending...' : 'Test Threat Alert'}</span>
          </button>
          
          <button
            onClick={handleTestEmail}
            disabled={isTesting || !emailConfig.smtpServer}
            className="px-4 py-3 bg-green-600 hover:bg-green-700 disabled:bg-green-800 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors flex items-center justify-center space-x-2"
          >
            <TestTube className="h-4 w-4" />
            <span>{isTesting ? 'Sending...' : 'Test System Alert'}</span>
          </button>
        </div>
      </div>

      {/* Setup Instructions */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h3 className="text-lg font-semibold text-white mb-4">Setup Instructions</h3>
        <div className="space-y-4 text-sm text-gray-300">
          <div className="bg-gray-900 rounded-lg p-4">
            <h4 className="font-medium text-white mb-2">Gmail Setup</h4>
            <ol className="list-decimal list-inside space-y-1">
              <li>Enable 2-factor authentication on your Gmail account</li>
              <li>Go to Google Account settings → Security → App passwords</li>
              <li>Generate an app password for "Mail"</li>
              <li>Use the generated app password in the password field above</li>
            </ol>
          </div>
          
          <div className="bg-gray-900 rounded-lg p-4">
            <h4 className="font-medium text-white mb-2">Outlook/Office 365 Setup</h4>
            <ol className="list-decimal list-inside space-y-1">
              <li>Use SMTP server: smtp-mail.outlook.com</li>
              <li>Port: 587 with TLS enabled</li>
              <li>Use your full email address as username</li>
              <li>Use your regular password or app password if 2FA is enabled</li>
            </ol>
          </div>
          
          <div className="bg-gray-900 rounded-lg p-4">
            <h4 className="font-medium text-white mb-2">Custom SMTP Server</h4>
            <ol className="list-decimal list-inside space-y-1">
              <li>Contact your IT administrator for SMTP server details</li>
              <li>Ensure the server allows authentication and relay</li>
              <li>Configure appropriate port (25, 465, 587, or 2525)</li>
              <li>Enable TLS if supported by your server</li>
            </ol>
          </div>
        </div>
      </div>
    </div>
  );
}