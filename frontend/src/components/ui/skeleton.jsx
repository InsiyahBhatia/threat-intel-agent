"use client";

import React from "react";
import { cn } from "../../lib/utils.js";

export default function Skeleton({ className, ...props }) {
  return <div className={cn("bg-surface-hover rounded-md animate-pulse", className)} {...props} />;
}
