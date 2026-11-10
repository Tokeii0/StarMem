use anyhow::{Result, ensure};

/// StarMem 默认允许使用的并行分析工作线程数。
pub const DEFAULT_MAX_ANALYSIS_THREADS: usize = 4;
/// StarMem 宿主默认使用的软内存上限（4 GiB）。
pub const DEFAULT_MAX_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// 分析调度线程和 Rayon 工作线程使用的栈大小。
///
/// Windows 未优化构建中，符号驱动的进程/令牌解析与嵌套 Rayon 扫描会产生
/// 明显更深的调用栈。64 MiB 是虚拟地址保留上限，不会在创建线程时立即提交
/// 同等物理内存；实际提交页仍受宿主私有内存 watchdog 约束。
pub const ANALYSIS_THREAD_STACK_BYTES: usize = 64 * 1024 * 1024;
pub const MIN_MEMORY_LIMIT_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_ANALYSIS_THREADS: usize = 64;

/// 宿主可配置的 StarMem 执行资源边界。
///
/// 内存字段是供宿主进程监控并触发协作取消的软上限；Rust 进程无法在
/// 不引入平台专用 Job Object/cgroup 的情况下对单个库施加硬内存配额。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisResourceLimits {
    pub max_threads: usize,
    pub max_memory_bytes: u64,
}

impl AnalysisResourceLimits {
    pub fn new(max_threads: usize, max_memory_bytes: u64) -> Result<Self> {
        ensure!(max_threads > 0, "StarMem 分析线程数必须大于零");
        ensure!(
            max_threads <= MAX_ANALYSIS_THREADS,
            "StarMem 分析线程数不能超过 {MAX_ANALYSIS_THREADS}"
        );
        ensure!(
            max_memory_bytes >= MIN_MEMORY_LIMIT_BYTES,
            "StarMem 内存上限不能低于 256 MiB"
        );
        Ok(Self {
            max_threads,
            max_memory_bytes,
        })
    }
}

impl Default for AnalysisResourceLimits {
    fn default() -> Self {
        Self {
            max_threads: DEFAULT_MAX_ANALYSIS_THREADS,
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
        }
    }
}

/// 每个宿主实例独立的 Rayon 分析池，避免修改进程全局 Rayon 配置。
pub struct AnalysisExecutor {
    limits: AnalysisResourceLimits,
    pool: rayon::ThreadPool,
}

impl AnalysisExecutor {
    pub fn new(limits: AnalysisResourceLimits) -> Result<Self> {
        let limits = AnalysisResourceLimits::new(limits.max_threads, limits.max_memory_bytes)?;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(limits.max_threads)
            .stack_size(ANALYSIS_THREAD_STACK_BYTES)
            .thread_name(|index| format!("starmem-analysis-{index}"))
            .build()?;
        Ok(Self { limits, pool })
    }

    pub fn limits(&self) -> AnalysisResourceLimits {
        self.limits
    }

    pub fn install<F, R>(&self, operation: F) -> R
    where
        F: FnOnce() -> R + Send,
        R: Send,
    {
        self.pool.install(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_reject_unsafe_values() {
        assert!(AnalysisResourceLimits::new(0, DEFAULT_MAX_MEMORY_BYTES).is_err());
        assert!(
            AnalysisResourceLimits::new(DEFAULT_MAX_ANALYSIS_THREADS, MIN_MEMORY_LIMIT_BYTES - 1)
                .is_err()
        );
        assert!(
            AnalysisResourceLimits::new(MAX_ANALYSIS_THREADS + 1, DEFAULT_MAX_MEMORY_BYTES)
                .is_err()
        );
    }

    #[test]
    fn executor_uses_the_configured_pool_width() {
        let limits = AnalysisResourceLimits::new(2, 1024 * 1024 * 1024).unwrap();
        let executor = AnalysisExecutor::new(limits).unwrap();
        assert_eq!(executor.limits().max_threads, 2);
        assert_eq!(executor.install(rayon::current_num_threads), 2);
    }
}
