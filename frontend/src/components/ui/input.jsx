"use client";

import React, { forwardRef } from "react";
import { cn } from "../../lib/utils.js";

const Input = forwardRef(({ className, ...props }, ref) => {
  return (
    <input
      ref={ref}
      className={cn(
        "flex h-10 w-full bg-surface border border-border rounded-lg px-3 py-2 text-sm text-text placeholder:text-muted-faint focus:ring-2 focus:ring-primary/20 focus:border-primary disabled:opacity-50 disabled:cursor-not-allowed",
        className,
      )}
      {...props}
    />
  );
});

Input.displayName = "Input";
export default Input;
