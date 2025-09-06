import React, { useState, useMemo, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ChevronUpIcon,
  ChevronDownIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  EllipsisVerticalIcon,
  TrashIcon,
  PencilIcon,
  EyeIcon,
  DocumentArrowDownIcon,
  FunnelIcon,
  MagnifyingGlassIcon,
  CheckIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';
import '../styles/cyberpunk-design-system.css';

// Table Header Component
function TableHeader({ columns, sortConfig, onSort, selectedItems, onSelectAll, totalItems }) {
  const isAllSelected = selectedItems.length === totalItems && totalItems > 0;
  const isIndeterminate = selectedItems.length > 0 && selectedItems.length < totalItems;

  return (
    <thead className="bg-bg-secondary border-b border-bg-tertiary">
      <tr>
        <th className="w-12 px-6 py-4">
          <div className="flex items-center">
            <input
              type="checkbox"
              checked={isAllSelected}
              ref={(input) => {
                if (input) input.indeterminate = isIndeterminate;
              }}
              onChange={(e) => onSelectAll(e.target.checked)}
              className="w-4 h-4 text-cyber-blue bg-bg-glass border-cyber-blue/30 rounded focus:ring-cyber-blue focus:ring-2"
            />
          </div>
        </th>
        {columns.map((column) => (
          <th
            key={column.key}
            className={`px-6 py-4 text-left text-xs font-medium text-text-secondary uppercase tracking-wider ${
              column.sortable ? 'cursor-pointer hover:text-text-primary transition-colors' : ''
            }`}
            onClick={() => column.sortable && onSort(column.key)}
          >
            <div className="flex items-center space-x-1">
              <span>{column.label}</span>
              {column.sortable && (
                <div className="flex flex-col">
                  <ChevronUpIcon
                    className={`w-3 h-3 ${
                      sortConfig.key === column.key && sortConfig.direction === 'asc'
                        ? 'text-cyber-blue'
                        : 'text-text-tertiary'
                    }`}
                  />
                  <ChevronDownIcon
                    className={`w-3 h-3 -mt-1 ${
                      sortConfig.key === column.key && sortConfig.direction === 'desc'
                        ? 'text-cyber-blue'
                        : 'text-text-tertiary'
                    }`}
                  />
                </div>
              )}
            </div>
          </th>
        ))}
        <th className="w-16 px-6 py-4">
          <span className="sr-only">Actions</span>
        </th>
      </tr>
    </thead>
  );
}

// Table Row Component
function TableRow({ item, columns, isSelected, onSelect, onAction, index }) {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const actions = [
    { icon: EyeIcon, label: 'View Details', action: 'view' },
    { icon: PencilIcon, label: 'Edit', action: 'edit' },
    { icon: DocumentArrowDownIcon, label: 'Export', action: 'export' },
    { icon: TrashIcon, label: 'Delete', action: 'delete', danger: true }
  ];

  return (
    <motion.tr
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.02 }}
      className={`border-b border-bg-tertiary hover:bg-bg-glass-subtle transition-colors duration-200 ${
        isSelected ? 'bg-cyber-blue/5' : ''
      }`}
    >
      <td className="w-12 px-6 py-4">
        <input
          type="checkbox"
          checked={isSelected}
          onChange={(e) => onSelect(item.id, e.target.checked)}
          className="w-4 h-4 text-cyber-blue bg-bg-glass border-cyber-blue/30 rounded focus:ring-cyber-blue focus:ring-2"
        />
      </td>
      {columns.map((column) => (
        <td key={column.key} className="px-6 py-4 whitespace-nowrap">
          {column.render ? column.render(item[column.key], item) : (
            <div className="text-sm text-text-primary">{item[column.key]}</div>
          )}
        </td>
      ))}
      <td className="w-16 px-6 py-4 relative">
        <button
          onClick={() => setIsMenuOpen(!isMenuOpen)}
          className="text-text-secondary hover:text-text-primary transition-colors p-1 rounded"
        >
          <EllipsisVerticalIcon className="w-5 h-5" />
        </button>
        
        <AnimatePresence>
          {isMenuOpen && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: -10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: -10 }}
              className="absolute right-0 top-full mt-1 w-48 glass-strong rounded-lg py-2 z-10"
            >
              {actions.map((action, actionIndex) => (
                <button
                  key={actionIndex}
                  onClick={() => {
                    onAction(action.action, item);
                    setIsMenuOpen(false);
                  }}
                  className={`w-full flex items-center space-x-3 px-4 py-2 text-sm transition-colors ${
                    action.danger
                      ? 'text-critical-red hover:bg-critical-red/10'
                      : 'text-text-secondary hover:text-text-primary hover:bg-bg-glass'
                  }`}
                >
                  <action.icon className="w-4 h-4" />
                  <span>{action.label}</span>
                </button>
              ))}
            </motion.div>
          )}
        </AnimatePresence>
      </td>
    </motion.tr>
  );
}

// Pagination Component
function Pagination({ currentPage, totalPages, onPageChange, itemsPerPage, onItemsPerPageChange }) {
  const pageNumbers = [];
  const maxVisiblePages = 5;
  
  let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
  let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
  
  if (endPage - startPage + 1 < maxVisiblePages) {
    startPage = Math.max(1, endPage - maxVisiblePages + 1);
  }
  
  for (let i = startPage; i <= endPage; i++) {
    pageNumbers.push(i);
  }

  return (
    <div className="flex items-center justify-between px-6 py-4 border-t border-bg-tertiary">
      <div className="flex items-center space-x-4">
        <span className="text-sm text-text-secondary">Rows per page:</span>
        <select
          value={itemsPerPage}
          onChange={(e) => onItemsPerPageChange(Number(e.target.value))}
          className="bg-bg-glass border border-cyber-blue/30 rounded px-3 py-1 text-sm text-text-primary focus:outline-none focus:border-cyber-blue"
        >
          <option value={10}>10</option>
          <option value={25}>25</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
        </select>
      </div>
      
      <div className="flex items-center space-x-2">
        <button
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage === 1}
          className="p-2 text-text-secondary hover:text-text-primary disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <ChevronLeftIcon className="w-5 h-5" />
        </button>
        
        {pageNumbers.map((number) => (
          <button
            key={number}
            onClick={() => onPageChange(number)}
            className={`px-3 py-1 rounded text-sm transition-colors ${
              currentPage === number
                ? 'bg-cyber-blue text-bg-primary'
                : 'text-text-secondary hover:text-text-primary hover:bg-bg-glass'
            }`}
          >
            {number}
          </button>
        ))}
        
        <button
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage === totalPages}
          className="p-2 text-text-secondary hover:text-text-primary disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <ChevronRightIcon className="w-5 h-5" />
        </button>
      </div>
      
      <div className="text-sm text-text-secondary">
        Page {currentPage} of {totalPages}
      </div>
    </div>
  );
}

// Bulk Actions Bar
function BulkActionsBar({ selectedCount, onBulkAction, onClearSelection }) {
  const bulkActions = [
    { label: 'Export Selected', action: 'export', icon: DocumentArrowDownIcon },
    { label: 'Mark as Resolved', action: 'resolve', icon: CheckIcon },
    { label: 'Delete Selected', action: 'delete', icon: TrashIcon, danger: true }
  ];

  return (
    <AnimatePresence>
      {selectedCount > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
          className="bg-cyber-blue/10 border border-cyber-blue/30 rounded-lg p-4 mb-4"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <span className="text-sm font-medium text-cyber-blue">
                {selectedCount} item{selectedCount !== 1 ? 's' : ''} selected
              </span>
              <div className="flex items-center space-x-2">
                {bulkActions.map((action, index) => (
                  <button
                    key={index}
                    onClick={() => onBulkAction(action.action)}
                    className={`flex items-center space-x-2 px-3 py-1 rounded text-sm transition-colors ${
                      action.danger
                        ? 'text-critical-red hover:bg-critical-red/10'
                        : 'text-cyber-blue hover:bg-cyber-blue/10'
                    }`}
                  >
                    <action.icon className="w-4 h-4" />
                    <span>{action.label}</span>
                  </button>
                ))}
              </div>
            </div>
            <button
              onClick={onClearSelection}
              className="text-text-secondary hover:text-text-primary transition-colors"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

// Main Enterprise Data Table Component
export default function EnterpriseDataTable({
  data = [],
  columns = [],
  title = "Data Table",
  searchable = true,
  filterable = true,
  exportable = true,
  onAction = () => {},
  onBulkAction = () => {}
}) {
  const [searchQuery, setSearchQuery] = useState('');
  const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(25);
  const [selectedItems, setSelectedItems] = useState([]);
  const [filters, setFilters] = useState({});

  // Filter and search data
  const filteredData = useMemo(() => {
    let filtered = data;

    // Apply search
    if (searchQuery) {
      filtered = filtered.filter(item =>
        columns.some(column =>
          String(item[column.key]).toLowerCase().includes(searchQuery.toLowerCase())
        )
      );
    }

    // Apply filters
    Object.entries(filters).forEach(([key, value]) => {
      if (value) {
        filtered = filtered.filter(item => item[key] === value);
      }
    });

    return filtered;
  }, [data, searchQuery, filters, columns]);

  // Sort data
  const sortedData = useMemo(() => {
    if (!sortConfig.key) return filteredData;

    return [...filteredData].sort((a, b) => {
      const aValue = a[sortConfig.key];
      const bValue = b[sortConfig.key];

      if (aValue < bValue) {
        return sortConfig.direction === 'asc' ? -1 : 1;
      }
      if (aValue > bValue) {
        return sortConfig.direction === 'asc' ? 1 : -1;
      }
      return 0;
    });
  }, [filteredData, sortConfig]);

  // Paginate data
  const paginatedData = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    return sortedData.slice(startIndex, startIndex + itemsPerPage);
  }, [sortedData, currentPage, itemsPerPage]);

  const totalPages = Math.ceil(sortedData.length / itemsPerPage);

  // Handlers
  const handleSort = useCallback((key) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc'
    }));
  }, []);

  const handleSelectItem = useCallback((id, selected) => {
    setSelectedItems(prev => 
      selected 
        ? [...prev, id]
        : prev.filter(item => item !== id)
    );
  }, []);

  const handleSelectAll = useCallback((selected) => {
    setSelectedItems(selected ? paginatedData.map(item => item.id) : []);
  }, [paginatedData]);

  const handleClearSelection = useCallback(() => {
    setSelectedItems([]);
  }, []);

  const handleBulkAction = useCallback((action) => {
    onBulkAction(action, selectedItems);
    setSelectedItems([]);
  }, [selectedItems, onBulkAction]);

  return (
    <div className="glass rounded-xl overflow-hidden">
      {/* Table Header */}
      <div className="px-6 py-4 border-b border-bg-tertiary">
        <div className="flex items-center justify-between">
          <h2 className="text-heading font-semibold gradient-text">{title}</h2>
          <div className="flex items-center space-x-4">
            {searchable && (
              <div className="relative">
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-text-tertiary" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search..."
                  className="pl-10 pr-4 py-2 bg-bg-glass border border-cyber-blue/30 rounded-lg text-sm text-text-primary placeholder-text-tertiary focus:border-cyber-blue focus:outline-none focus:ring-2 focus:ring-cyber-blue/20"
                />
              </div>
            )}
            {filterable && (
              <button className="p-2 text-text-secondary hover:text-text-primary transition-colors">
                <FunnelIcon className="w-5 h-5" />
              </button>
            )}
            {exportable && (
              <button className="p-2 text-text-secondary hover:text-text-primary transition-colors">
                <DocumentArrowDownIcon className="w-5 h-5" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Bulk Actions */}
      <div className="px-6 pt-4">
        <BulkActionsBar
          selectedCount={selectedItems.length}
          onBulkAction={handleBulkAction}
          onClearSelection={handleClearSelection}
        />
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-bg-tertiary">
          <TableHeader
            columns={columns}
            sortConfig={sortConfig}
            onSort={handleSort}
            selectedItems={selectedItems}
            onSelectAll={handleSelectAll}
            totalItems={paginatedData.length}
          />
          <tbody className="bg-bg-primary divide-y divide-bg-tertiary">
            {paginatedData.map((item, index) => (
              <TableRow
                key={item.id}
                item={item}
                columns={columns}
                isSelected={selectedItems.includes(item.id)}
                onSelect={handleSelectItem}
                onAction={onAction}
                index={index}
              />
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <Pagination
        currentPage={currentPage}
        totalPages={totalPages}
        onPageChange={setCurrentPage}
        itemsPerPage={itemsPerPage}
        onItemsPerPageChange={setItemsPerPage}
      />
    </div>
  );
}