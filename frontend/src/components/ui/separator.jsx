"use client";

import React from "react";
import { cn } from "../../lib/utils.js";

export default function Separator({ className, ...props }) {
  return <div className={cn("h-px bg-border my-1", className)} {...props} />;
}
