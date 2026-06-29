"use client";

import React from "react";
import { cn } from "../../lib/utils.js";

export function Card({ className, ...props }) {
  return <div className={cn("bg-surface-light border border-border rounded-xl", className)} {...props} />;
}

export function CardHeader({ className, ...props }) {
  return <div className={cn("flex items-center gap-3 p-5 pb-0", className)} {...props} />;
}

export function CardTitle({ className, ...props }) {
  return <h3 className={cn("text-[15px] font-semibold text-text", className)} {...props} />;
}

export function CardDescription({ className, ...props }) {
  return <p className={cn("text-xs text-muted mt-0.5", className)} {...props} />;
}

export function CardContent({ className, ...props }) {
  return <div className={cn("p-5 pt-3", className)} {...props} />;
}

export function CardFooter({ className, ...props }) {
  return <div className={cn("p-5 pt-0 flex items-center gap-2", className)} {...props} />;
}

export default Card;
