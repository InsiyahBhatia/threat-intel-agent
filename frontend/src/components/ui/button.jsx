"use client";

import React, { forwardRef } from "react";
import { cn } from "../../lib/utils.js";

const variantStyles = {
  primary: "bg-primary hover:bg-primary-hover text-white",
  secondary: "bg-surface-light border border-border hover:bg-surface-hover",
  ghost: "hover:bg-surface-light",
  danger: "bg-danger hover:bg-red-700 text-white",
  outline: "border border-border text-muted hover:text-text hover:bg-surface-light",
};

const sizeStyles = {
  sm: "h-8 px-3 text-xs",
  md: "h-10 px-4 text-sm",
  lg: "h-12 px-6 text-base",
};

const Button = forwardRef(({ className, variant = "primary", size = "md", loading, disabled, children, ...props }, ref) => {
  return (
    <button
      ref={ref}
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-primary/20",
        variantStyles[variant],
        sizeStyles[size],
        (disabled || loading) && "opacity-50 cursor-not-allowed",
        className,
      )}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      )}
      {children}
    </button>
  );
});

Button.displayName = "Button";
export default Button;
