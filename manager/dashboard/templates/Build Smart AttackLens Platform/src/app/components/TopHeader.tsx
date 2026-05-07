import { Bell, ChevronDown } from "lucide-react";

export function TopHeader() {
  return (
    <div className="h-14 bg-white border-b border-[--gray-200] flex items-center justify-between px-6 shadow-sm">
      <div className="flex items-center gap-2 text-[13px]">
        <span className="text-[--gray-500]">Dashboard</span>
        <span className="text-[--gray-300]">›</span>
        <span className="font-semibold text-[--gray-800]">Overview</span>
      </div>

      <div className="flex items-center gap-4">
        <button className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-[--gray-700] bg-white border border-[--gray-200] rounded-lg hover:bg-[--gray-50] hover:border-[--gray-300] shadow-sm transition-all">
          Last 24h
          <ChevronDown className="w-3 h-3" />
        </button>

        <div className="flex items-center gap-2 px-3 py-1.5 bg-[--green-50] rounded-lg border border-[--green-600]/20">
          <div className="w-2 h-2 rounded-full bg-[--green-600] animate-pulse shadow-sm"></div>
          <span className="text-xs font-medium text-[--green-700]">Updated 4s ago</span>
        </div>

        <div className="relative p-2 hover:bg-[--gray-50] rounded-lg cursor-pointer transition-colors">
          <Bell className="w-5 h-5 text-[--gray-400] hover:text-[--gray-600]" />
          <div className="absolute top-1 right-1 w-2.5 h-2.5 bg-gradient-to-br from-[--red-500] to-[--red-600] rounded-full border-2 border-white shadow-md"></div>
        </div>

        <div className="w-8 h-8 rounded-full bg-gradient-to-br from-[--blue-500] to-[--indigo-600] flex items-center justify-center text-xs font-bold text-white cursor-pointer shadow-md hover:shadow-lg transition-shadow">
          JD
        </div>
      </div>
    </div>
  );
}
