import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ExclamationCircleIcon,
  CheckCircleIcon,
  EyeIcon,
  EyeSlashIcon,
  InformationCircleIcon,
  DocumentDuplicateIcon,
  ClockIcon,
  CloudArrowUpIcon
} from '@heroicons/react/24/outline';
import { useNotifications } from './NotificationSystem';
import '../styles/cyberpunk-design-system.css';

// Form Field Component
function FormField({
  label,
  name,
  type = 'text',
  value,
  onChange,
  onBlur,
  error,
  warning,
  success,
  required = false,
  disabled = false,
  placeholder,
  helpText,
  options = [],
  dependencies = [],
  validation = {},
  autoSave = false,
  className = ''
}) {
  const [showPassword, setShowPassword] = useState(false);
  const [isFocused, setIsFocused] = useState(false);
  const [isValidating, setIsValidating] = useState(false);
  const inputRef = useRef(null);

  const fieldId = `field-${name}`;
  const hasError = !!error;
  const hasWarning = !!warning;
  const hasSuccess = !!success;

  const getFieldStatus = () => {
    if (hasError) return 'error';
    if (hasWarning) return 'warning';
    if (hasSuccess) return 'success';
    return 'default';
  };

  const getFieldColors = () => {
    const status = getFieldStatus();
    switch (status) {
      case 'error':
        return {
          border: 'border-critical-red focus:border-critical-red',
          ring: 'focus:ring-critical-red/20',
          text: 'text-critical-red'
        };
      case 'warning':
        return {
          border: 'border-high-orange focus:border-high-orange',
          ring: 'focus:ring-high-orange/20',
          text: 'text-high-orange'
        };
      case 'success':
        return {
          border: 'border-success-green focus:border-success-green',
          ring: 'focus:ring-success-green/20',
          text: 'text-success-green'
        };
      default:
        return {
          border: 'border-cyber-blue/30 focus:border-cyber-blue',
          ring: 'focus:ring-cyber-blue/20',
          text: 'text-cyber-blue'
        };
    }
  };

  const colors = getFieldColors();

  const handleChange = (e) => {
    const newValue = e.target.value;
    onChange(name, newValue);
    
    if (validation.realTime) {
      setIsValidating(true);
      // Simulate validation delay
      setTimeout(() => setIsValidating(false), 500);
    }
  };

  const handleBlur = (e) => {
    setIsFocused(false);
    if (onBlur) {
      onBlur(name, e.target.value);
    }
  };

  const renderInput = () => {
    const baseClasses = `w-full px-4 py-3 bg-bg-glass ${colors.border} rounded-lg text-text-primary placeholder-text-tertiary focus:outline-none focus:ring-2 ${colors.ring} transition-all duration-300 ${disabled ? 'opacity-50 cursor-not-allowed' : ''} ${className}`;

    switch (type) {
      case 'textarea':
        return (
          <textarea
            ref={inputRef}
            id={fieldId}
            name={name}
            value={value || ''}
            onChange={handleChange}
            onBlur={handleBlur}
            onFocus={() => setIsFocused(true)}
            placeholder={placeholder}
            disabled={disabled}
            required={required}
            rows={4}
            className={`${baseClasses} resize-vertical`}
          />
        );
      
      case 'select':
        return (
          <select
            ref={inputRef}
            id={fieldId}
            name={name}
            value={value || ''}
            onChange={handleChange}
            onBlur={handleBlur}
            onFocus={() => setIsFocused(true)}
            disabled={disabled}
            required={required}
            className={baseClasses}
          >
            <option value="">{placeholder || 'Select an option...'}</option>
            {options.map((option, index) => (
              <option key={index} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        );
      
      case 'password':
        return (
          <div className="relative">
            <input
              ref={inputRef}
              id={fieldId}
              name={name}
              type={showPassword ? 'text' : 'password'}
              value={value || ''}
              onChange={handleChange}
              onBlur={handleBlur}
              onFocus={() => setIsFocused(true)}
              placeholder={placeholder}
              disabled={disabled}
              required={required}
              className={`${baseClasses} pr-12`}
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-text-tertiary hover:text-text-primary transition-colors"
            >
              {showPassword ? (
                <EyeSlashIcon className="w-5 h-5" />
              ) : (
                <EyeIcon className="w-5 h-5" />
              )}
            </button>
          </div>
        );
      
      case 'checkbox':
        return (
          <label className="flex items-center space-x-3 cursor-pointer">
            <input
              ref={inputRef}
              id={fieldId}
              name={name}
              type="checkbox"
              checked={value || false}
              onChange={(e) => onChange(name, e.target.checked)}
              onBlur={handleBlur}
              onFocus={() => setIsFocused(true)}
              disabled={disabled}
              required={required}
              className={`w-4 h-4 text-cyber-blue bg-bg-glass border-cyber-blue/30 rounded focus:ring-cyber-blue focus:ring-2 ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
            />
            <span className="text-text-primary">{label}</span>
          </label>
        );
      
      default:
        return (
          <input
            ref={inputRef}
            id={fieldId}
            name={name}
            type={type}
            value={value || ''}
            onChange={handleChange}
            onBlur={handleBlur}
            onFocus={() => setIsFocused(true)}
            placeholder={placeholder}
            disabled={disabled}
            required={required}
            className={baseClasses}
          />
        );
    }
  };

  const renderStatusIcon = () => {
    if (isValidating) {
      return (
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
          className="w-5 h-5 border-2 border-cyber-blue border-t-transparent rounded-full"
        />
      );
    }
    
    if (hasError) {
      return <ExclamationCircleIcon className="w-5 h-5 text-critical-red" />;
    }
    
    if (hasWarning) {
      return <ExclamationCircleIcon className="w-5 h-5 text-high-orange" />;
    }
    
    if (hasSuccess) {
      return <CheckCircleIcon className="w-5 h-5 text-success-green" />;
    }
    
    return null;
  };

  if (type === 'checkbox') {
    return (
      <div className="space-y-2">
        {renderInput()}
        {(error || warning || helpText) && (
          <div className="space-y-1">
            {error && (
              <p className="text-sm text-critical-red flex items-center space-x-1">
                <ExclamationCircleIcon className="w-4 h-4" />
                <span>{error}</span>
              </p>
            )}
            {warning && (
              <p className="text-sm text-high-orange flex items-center space-x-1">
                <ExclamationCircleIcon className="w-4 h-4" />
                <span>{warning}</span>
              </p>
            )}
            {helpText && (
              <p className="text-sm text-text-tertiary flex items-center space-x-1">
                <InformationCircleIcon className="w-4 h-4" />
                <span>{helpText}</span>
              </p>
            )}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {label && (
        <label htmlFor={fieldId} className="block text-sm font-medium text-text-secondary">
          {label}
          {required && <span className="text-critical-red ml-1">*</span>}
          {autoSave && (
            <span className="ml-2 text-xs text-text-tertiary flex items-center space-x-1">
              <CloudArrowUpIcon className="w-3 h-3" />
              <span>Auto-save</span>
            </span>
          )}
        </label>
      )}
      
      <div className="relative">
        {renderInput()}
        
        {(hasError || hasWarning || hasSuccess || isValidating) && (
          <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
            {renderStatusIcon()}
          </div>
        )}
      </div>
      
      <AnimatePresence>
        {(error || warning || success || helpText) && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="space-y-1"
          >
            {error && (
              <p className="text-sm text-critical-red flex items-center space-x-1">
                <ExclamationCircleIcon className="w-4 h-4" />
                <span>{error}</span>
              </p>
            )}
            {warning && (
              <p className="text-sm text-high-orange flex items-center space-x-1">
                <ExclamationCircleIcon className="w-4 h-4" />
                <span>{warning}</span>
              </p>
            )}
            {success && (
              <p className="text-sm text-success-green flex items-center space-x-1">
                <CheckCircleIcon className="w-4 h-4" />
                <span>{success}</span>
              </p>
            )}
            {helpText && !error && !warning && (
              <p className="text-sm text-text-tertiary flex items-center space-x-1">
                <InformationCircleIcon className="w-4 h-4" />
                <span>{helpText}</span>
              </p>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// Form Section Component
function FormSection({ title, description, children, collapsible = false, defaultExpanded = true }) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  return (
    <div className="glass p-6 rounded-xl">
      <div className="mb-6">
        {collapsible ? (
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="w-full flex items-center justify-between text-left"
          >
            <div>
              <h3 className="text-heading font-semibold gradient-text">{title}</h3>
              {description && (
                <p className="text-sm text-text-secondary mt-1">{description}</p>
              )}
            </div>
            <motion.div
              animate={{ rotate: isExpanded ? 180 : 0 }}
              transition={{ duration: 0.2 }}
            >
              <ChevronDownIcon className="w-5 h-5 text-text-tertiary" />
            </motion.div>
          </button>
        ) : (
          <div>
            <h3 className="text-heading font-semibold gradient-text">{title}</h3>
            {description && (
              <p className="text-sm text-text-secondary mt-1">{description}</p>
            )}
          </div>
        )}
      </div>
      
      <AnimatePresence>
        {(!collapsible || isExpanded) && (
          <motion.div
            initial={collapsible ? { opacity: 0, height: 0 } : false}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="space-y-6"
          >
            {children}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// Auto-save Hook
function useAutoSave(data, onSave, delay = 2000) {
  const [isSaving, setIsSaving] = useState(false);
  const [lastSaved, setLastSaved] = useState(null);
  const timeoutRef = useRef(null);
  const notifications = useNotifications();

  const save = useCallback(async () => {
    setIsSaving(true);
    try {
      await onSave(data);
      setLastSaved(new Date());
      notifications.success('Changes saved automatically', { duration: 2000 });
    } catch (error) {
      notifications.error('Failed to auto-save changes');
    } finally {
      setIsSaving(false);
    }
  }, [data, onSave, notifications]);

  useEffect(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }
    
    timeoutRef.current = setTimeout(() => {
      if (Object.keys(data).length > 0) {
        save();
      }
    }, delay);

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [data, delay, save]);

  return { isSaving, lastSaved };
}

// Main Enterprise Form Component
export default function EnterpriseForm({
  title,
  description,
  fields = [],
  sections = [],
  initialData = {},
  onSubmit,
  onCancel,
  autoSave = false,
  autoSaveDelay = 2000,
  validation = {},
  className = ''
}) {
  const [formData, setFormData] = useState(initialData);
  const [errors, setErrors] = useState({});
  const [warnings, setWarnings] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isDirty, setIsDirty] = useState(false);
  const notifications = useNotifications();

  // Auto-save functionality
  const { isSaving, lastSaved } = useAutoSave(
    formData,
    async (data) => {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      console.log('Auto-saved:', data);
    },
    autoSave ? autoSaveDelay : 0
  );

  const handleFieldChange = useCallback((name, value) => {
    setFormData(prev => ({ ...prev, [name]: value }));
    setIsDirty(true);
    
    // Clear errors for this field
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: null }));
    }
    
    // Real-time validation
    if (validation[name]) {
      const fieldValidation = validation[name];
      if (fieldValidation.required && !value) {
        setErrors(prev => ({ ...prev, [name]: 'This field is required' }));
      } else if (fieldValidation.pattern && !fieldValidation.pattern.test(value)) {
        setErrors(prev => ({ ...prev, [name]: fieldValidation.message || 'Invalid format' }));
      } else if (fieldValidation.minLength && value.length < fieldValidation.minLength) {
        setWarnings(prev => ({ ...prev, [name]: `Minimum ${fieldValidation.minLength} characters required` }));
      } else {
        setWarnings(prev => ({ ...prev, [name]: null }));
      }
    }
  }, [errors, validation]);

  const handleFieldBlur = useCallback((name, value) => {
    // Perform validation on blur
    if (validation[name]) {
      const fieldValidation = validation[name];
      if (fieldValidation.required && !value) {
        setErrors(prev => ({ ...prev, [name]: 'This field is required' }));
      }
    }
  }, [validation]);

  const validateForm = () => {
    const newErrors = {};
    
    // Validate all fields
    Object.keys(validation).forEach(fieldName => {
      const fieldValidation = validation[fieldName];
      const value = formData[fieldName];
      
      if (fieldValidation.required && !value) {
        newErrors[fieldName] = 'This field is required';
      } else if (fieldValidation.pattern && value && !fieldValidation.pattern.test(value)) {
        newErrors[fieldName] = fieldValidation.message || 'Invalid format';
      }
    });
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      notifications.error('Please fix the errors before submitting');
      return;
    }
    
    setIsSubmitting(true);
    
    try {
      await onSubmit(formData);
      notifications.success('Form submitted successfully!');
      setIsDirty(false);
    } catch (error) {
      notifications.error('Failed to submit form. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const renderField = (field) => {
    return (
      <FormField
        key={field.name}
        {...field}
        value={formData[field.name]}
        onChange={handleFieldChange}
        onBlur={handleFieldBlur}
        error={errors[field.name]}
        warning={warnings[field.name]}
        autoSave={autoSave}
      />
    );
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Form Header */}
      {(title || description) && (
        <div className="mb-8">
          {title && (
            <h1 className="text-display font-bold gradient-text mb-2">{title}</h1>
          )}
          {description && (
            <p className="text-body text-text-secondary">{description}</p>
          )}
        </div>
      )}

      {/* Auto-save Status */}
      {autoSave && (
        <div className="flex items-center justify-between p-3 bg-bg-glass-subtle rounded-lg">
          <div className="flex items-center space-x-2">
            <CloudArrowUpIcon className="w-4 h-4 text-cyber-blue" />
            <span className="text-sm text-text-secondary">Auto-save enabled</span>
          </div>
          <div className="flex items-center space-x-2">
            {isSaving && (
              <div className="flex items-center space-x-2 text-cyber-blue">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                  className="w-3 h-3 border border-cyber-blue border-t-transparent rounded-full"
                />
                <span className="text-xs">Saving...</span>
              </div>
            )}
            {lastSaved && !isSaving && (
              <div className="flex items-center space-x-1 text-success-green">
                <CheckCircleIcon className="w-3 h-3" />
                <span className="text-xs">Saved {lastSaved.toLocaleTimeString()}</span>
              </div>
            )}
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Render Sections */}
        {sections.length > 0 ? (
          sections.map((section, index) => (
            <FormSection key={index} {...section}>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {section.fields.map(renderField)}
              </div>
            </FormSection>
          ))
        ) : (
          /* Render Fields Directly */
          <div className="glass p-6 rounded-xl">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {fields.map(renderField)}
            </div>
          </div>
        )}

        {/* Form Actions */}
        <div className="flex items-center justify-between pt-6 border-t border-bg-tertiary">
          <div className="flex items-center space-x-4">
            {isDirty && (
              <div className="flex items-center space-x-2 text-high-orange">
                <ClockIcon className="w-4 h-4" />
                <span className="text-sm">Unsaved changes</span>
              </div>
            )}
          </div>
          
          <div className="flex items-center space-x-4">
            {onCancel && (
              <button
                type="button"
                onClick={onCancel}
                className="btn-ghost px-6 py-3"
                disabled={isSubmitting}
              >
                Cancel
              </button>
            )}
            <button
              type="submit"
              className="btn-cyber px-6 py-3 flex items-center space-x-2"
              disabled={isSubmitting || Object.keys(errors).length > 0}
            >
              {isSubmitting ? (
                <>
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                    className="w-4 h-4 border-2 border-white border-t-transparent rounded-full"
                  />
                  <span>Submitting...</span>
                </>
              ) : (
                <span>Submit</span>
              )}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}

// Export field validation helpers
export const validators = {
  required: (message = 'This field is required') => ({
    required: true,
    message
  }),
  
  email: (message = 'Please enter a valid email address') => ({
    pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    message
  }),
  
  minLength: (length, message) => ({
    minLength: length,
    message: message || `Minimum ${length} characters required`
  }),
  
  maxLength: (length, message) => ({
    maxLength: length,
    message: message || `Maximum ${length} characters allowed`
  }),
  
  pattern: (regex, message = 'Invalid format') => ({
    pattern: regex,
    message
  })
};