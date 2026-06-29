"use client";

import React from "react";
import { cn } from "../../lib/utils.js";

const variantStyles = {
  default: "bg-surface-hover text-muted",
  primary: "bg-primary-light text-primary",
  success: "bg-success-light text-success",
  warning: "bg-warning-light text-warning",
  danger: "bg-danger-light text-danger",
};

const sizeStyles = {
  sm: "px-1.5 py-0.5 text-[10px]",
  md: "px-2.5 py-1 text-xs",
};

export default function Badge({ className, variant = "default", size = "md", ...props }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md font-mono font-semibold",
        variantStyles[variant],
        sizeStyles[size],
        className,
      )}
      {...props}
    />
  );
}
