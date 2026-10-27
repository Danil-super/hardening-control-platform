'use client';
import * as Primitive from '@radix-ui/react-select';
import { Check, ChevronDown } from 'lucide-react';
import { Children, isValidElement, useLayoutEffect, useRef, useState, type ReactNode, type ButtonHTMLAttributes } from 'react';

type Props = Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'onChange' | 'value' | 'defaultValue'> & {
  required?: boolean; value?: string; defaultValue?: string; onValueChange?: (value: string) => void;
  fitContent?: boolean;
};
type OptionProps = { value?: string; disabled?: boolean; label?: string; children?: ReactNode };
const emptyValue = '__hcp_empty_selection__';
function options(children: ReactNode): Array<{ value: string; label: ReactNode; disabled?: boolean; group?: string }> {
  return Children.toArray(children).flatMap(child => {
    if (!isValidElement<OptionProps>(child)) return [];
    if (child.type === 'optgroup') return options(child.props.children).map(item => ({ ...item, group: child.props.label, disabled: child.props.disabled || item.disabled }));
    if (child.type === 'option') return [{ value: String(child.props.value ?? child.props.children ?? ''), label: child.props.children, disabled: child.props.disabled }];
    return options(child.props.children);
  });
}
export function Select({ children, value, defaultValue, onValueChange, className = '', name, required, disabled, form, fitContent = false, ...props }: Props) {
  const items = options(children);
  const [internal, setInternal] = useState(defaultValue ?? items[0]?.value ?? '');
  const [open, setOpen] = useState(false);
  const [sideOffset, setSideOffset] = useState(6);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const viewportRef = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    if (!open || !fitContent) return;
    // A short list may overlap its trigger when neither side has enough room.
    // Measure the full list so Floating UI can fit it without clipping items.
    const update = () => {
      const trigger = triggerRef.current?.getBoundingClientRect();
      const viewport = viewportRef.current;
      if (!trigger || !viewport) return;
      const available = Math.max(trigger.top - 12, window.innerHeight - trigger.bottom - 12);
      setSideOffset(Math.min(6, available - viewport.scrollHeight - 2));
    };
    update();
    const frame = requestAnimationFrame(update);
    const observer = new ResizeObserver(update);
    if (viewportRef.current) observer.observe(viewportRef.current);
    window.addEventListener('resize', update);
    return () => { cancelAnimationFrame(frame); observer.disconnect(); window.removeEventListener('resize', update); };
  }, [open, fitContent]);
  const selected = value ?? internal;
  const change = (next: string) => { const actual = next === emptyValue ? '' : next; setInternal(actual); onValueChange?.(actual); };
  return <Primitive.Root value={selected || emptyValue} onValueChange={change} disabled={disabled} open={open} onOpenChange={setOpen}>
    <Primitive.Trigger {...props} ref={triggerRef} aria-required={required || undefined} className={`hcp-select ${className}`}>
      <Primitive.Value />
      <Primitive.Icon className="ml-3 shrink-0 text-slate-400"><ChevronDown size={16} aria-hidden="true" /></Primitive.Icon>
    </Primitive.Trigger>
    {name || required ? <select name={name} form={form} required={required} disabled={disabled} value={selected} onChange={event => change(event.target.value)} tabIndex={-1} aria-hidden="true" className="sr-only">
      {items.map(item => <option key={item.value} value={item.value} disabled={item.disabled}>{item.label}</option>)}
    </select> : null}
    <Primitive.Portal><Primitive.Content position="popper" sideOffset={fitContent ? sideOffset : 6} collisionPadding={12} className="hcp-select-menu">
      <Primitive.Viewport ref={viewportRef} className="p-1">
        {items.map((item, index) => <div key={item.value}>
          {item.group && item.group !== items[index - 1]?.group ? <p className="hcp-select-group-label">{item.group}</p> : null}
          <Primitive.Item value={item.value || emptyValue} disabled={item.disabled} className="hcp-select-item">
            <Primitive.ItemText>{item.label}</Primitive.ItemText>
            <Primitive.ItemIndicator className="ml-4 shrink-0 text-sky-300"><Check size={16} aria-hidden="true" /></Primitive.ItemIndicator>
          </Primitive.Item>
        </div>)}
      </Primitive.Viewport>
    </Primitive.Content></Primitive.Portal>
  </Primitive.Root>;
}
